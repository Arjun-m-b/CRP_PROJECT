# reencrypt.py
# Cross-server re-encryption orchestrator for HYDRA
# Called after a ratchet fires to ensure both servers
# have identical re-encrypted records at the new epoch.
#
# Can be:
#   1. Imported and called by server_a/app.py directly
#   2. Run standalone for manual recovery:
#      python reencrypt.py --old-epoch 2 --new-epoch 3

import sys
import os
import time
import json
import argparse

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding='utf-8')

from core.xchacha20 import encrypt, decrypt, generate_nonce
from core.hkdf      import ratchet, zero_key
from core.audit     import (
    AuditLog,
    RE_ENCRYPT_START,
    RE_ENCRYPT_COMPLETE,
    RATCHET_TRIGGERED,
    RATCHET_COMPLETE,
)


# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

SERVER_A_URL   = "http://127.0.0.1:5001"
SERVER_B_URL   = "http://127.0.0.1:5002"

# Audit log for the orchestrator itself
AUDIT_PATH = os.path.join(ROOT, "reencrypt_audit.json")


# ─────────────────────────────────────────────
# HTTP HELPERS
# ─────────────────────────────────────────────

def _post(url: str, payload: dict, timeout: int = 10) -> dict:
    """
    POST JSON to a URL. Returns parsed response dict.
    Raises RuntimeError if request fails or returns non-200.
    """
    try:
        import requests
        resp = requests.post(url, json=payload, timeout=timeout)
        if resp.status_code != 200:
            raise RuntimeError(
                f"POST {url} returned {resp.status_code}: {resp.text}"
            )
        return resp.json()
    except Exception as e:
        raise RuntimeError(f"POST {url} failed: {e}")


def _get(url: str, timeout: int = 10) -> dict:
    """
    GET a URL. Returns parsed response dict.
    Raises RuntimeError if request fails or returns non-200.
    """
    try:
        import requests
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            raise RuntimeError(
                f"GET {url} returned {resp.status_code}: {resp.text}"
            )
        return resp.json()
    except Exception as e:
        raise RuntimeError(f"GET {url} failed: {e}")


# ─────────────────────────────────────────────
# RECORD HELPERS
# ─────────────────────────────────────────────

def _fetch_all_records(server_url: str) -> list:
    """
    Fetch all encrypted record blobs from a server.

    Calls GET /fetch/all to get IDs, then GET /fetch/<id>
    for each to get the full ciphertext.

    Returns list of full record dicts:
    [
        {
            record_id, epoch, nonce (bytes),
            ciphertext (bytes), mac_tag (bytes),
            created_at, updated_at
        },
        ...
    ]
    """
    # Get list of all record IDs
    meta_resp = _get(f"{server_url}/fetch/all")
    records_meta = meta_resp.get("records", [])

    if not records_meta:
        return []

    full_records = []
    for meta in records_meta:
        rid = meta["id"]
        try:
            rec_resp = _get(f"{server_url}/fetch/{rid}")
            full_records.append({
                "record_id":  rec_resp["record_id"],
                "epoch":      rec_resp["epoch"],
                "nonce":      bytes.fromhex(rec_resp["nonce"]),
                "ciphertext": bytes.fromhex(rec_resp["ciphertext"]),
                "mac_tag":    bytes.fromhex(rec_resp["mac_tag"]),
                "created_at": rec_resp["created_at"],
                "updated_at": rec_resp["updated_at"],
            })
        except Exception as e:
            print(f"[reencrypt] WARNING: Could not fetch {rid}: {e}")

    return full_records


def _push_record(server_url: str, record_id: str,
                  nonce: bytes, ciphertext: bytes,
                  mac_tag: bytes) -> str:
    """
    Push a re-encrypted record to a server via POST /store.

    Returns:
        "ok"       — successfully stored
        "isolated" — server returned 503 (intentionally isolated, not an error)
        "error"    — unexpected failure
    """
    try:
        import requests
        resp = requests.post(
            f"{server_url}/store",
            json={
                "record_id":  record_id,
                "nonce":      nonce.hex(),
                "ciphertext": ciphertext.hex(),
                "mac_tag":    mac_tag.hex(),
            },
            timeout=10,
        )
        if resp.status_code == 200:
            return "ok"
        elif resp.status_code == 503:
            # Server is intentionally isolated — it will derive the same
            # K_n+1 independently via /promote and pull records via /internal/sync.
            print(f"[reencrypt] {server_url} is isolated (503) — skipping push "
                  f"for {record_id} (peer will sync on promotion)")
            return "isolated"
        else:
            print(f"[reencrypt] WARNING: Push to {server_url} returned "
                  f"{resp.status_code} for {record_id}")
            return "error"
    except Exception as e:
        print(f"[reencrypt] WARNING: Push to {server_url} failed "
              f"for {record_id}: {e}")
        return "error"


# ─────────────────────────────────────────────
# CORE RE-ENCRYPTION
# ─────────────────────────────────────────────

def reencrypt_records(
    records:   list,
    old_key:   bytes,
    new_key:   bytes,
    old_epoch: int,
    new_epoch: int,
    server_id: str = "orchestrator"
) -> tuple:
    """
    Decrypt all records with old_key, re-encrypt with new_key.

    This is the pure cryptographic step — no network calls.
    Each record gets a brand new random nonce on re-encryption.

    Args:
        records:   list of record dicts (from _fetch_all_records)
        old_key:   32-byte key for epoch N
        new_key:   32-byte key for epoch N+1
        old_epoch: must match records' epoch field
        new_epoch: target epoch after re-encryption
        server_id: label for log messages

    Returns:
        (reencrypted: list, failed: list)

        reencrypted: list of dicts with new nonce/ciphertext/tag
        failed:      list of record_ids that failed
    """
    reencrypted = []
    failed      = []

    # Filter to only records at old_epoch
    # (safety check — should already be filtered by caller)
    target = [r for r in records if r["epoch"] == old_epoch]

    print(f"[reencrypt] Re-encrypting {len(target)} records "
          f"epoch {old_epoch} -> {new_epoch}...")

    for rec in target:
        rid = rec["record_id"]
        try:
            # Step 1: decrypt with old key
            plaintext = decrypt(
                old_key,
                rec["nonce"],
                rec["ciphertext"],
                rec["mac_tag"]
            )

            # Step 2: re-encrypt with new key + FRESH nonce
            # Never reuse a nonce — always generate new one
            new_nonce, new_ct, new_tag = encrypt(new_key, plaintext)

            reencrypted.append({
                "record_id":  rid,
                "epoch":      new_epoch,
                "nonce":      new_nonce,
                "ciphertext": new_ct,
                "mac_tag":    new_tag,
            })

        except ValueError as e:
            # MAC verification failed — ciphertext corrupted
            print(f"[reencrypt] ERROR: MAC failed for {rid}: {e}")
            failed.append(rid)

        except Exception as e:
            print(f"[reencrypt] ERROR: Re-encrypt failed for {rid}: {e}")
            failed.append(rid)

    print(f"[reencrypt] Done: {len(reencrypted)} success, "
          f"{len(failed)} failed")

    return reencrypted, failed


# ─────────────────────────────────────────────
# ORCHESTRATION
# ─────────────────────────────────────────────

def run_reencryption(
    old_key:       bytes,
    new_key:       bytes,
    old_epoch:     int,
    new_epoch:     int,
    source_server: str = "server_a"
) -> dict:
    """
    Full cross-server re-encryption orchestration.

    Fetches records from source server, re-encrypts them,
    then pushes re-encrypted records to BOTH servers.

    Args:
        old_key:       32-byte encryption key for epoch N
        new_key:       32-byte encryption key for epoch N+1
        old_epoch:     current epoch number
        new_epoch:     new epoch number after ratchet
        source_server: which server to pull records from
                       "server_a" or "server_b"

    Returns:
        Result summary dict:
        {
            "success":      bool,
            "total":        int,
            "reencrypted":  int,
            "failed":       int,
            "pushed_a":     int,
            "pushed_b":     int,
            "duration_ms":  float,
        }
    """
    audit = AuditLog(AUDIT_PATH)
    start_time = time.time()

    source_url = (SERVER_A_URL if source_server == "server_a"
                  else SERVER_B_URL)

    print(f"\n[reencrypt] ── Starting re-encryption ──")
    print(f"[reencrypt] Source:    {source_server} ({source_url})")
    print(f"[reencrypt] Epoch:     {old_epoch} -> {new_epoch}")

    # ── Step 1: Fetch all records from source server ──
    print(f"\n[reencrypt] Step 1: Fetching records from {source_server}...")
    try:
        records = _fetch_all_records(source_url)
    except RuntimeError as e:
        print(f"[reencrypt] FATAL: Could not fetch records: {e}")
        return {
            "success": False,
            "error":   str(e),
            "total":   0,
        }

    # Filter to records at old_epoch only
    epoch_records = [r for r in records if r["epoch"] == old_epoch]
    total = len(epoch_records)
    print(f"[reencrypt] Found {total} records at epoch {old_epoch}")

    if total == 0:
        print(f"[reencrypt] Nothing to re-encrypt at epoch {old_epoch}")
        return {
            "success":     True,
            "total":       0,
            "reencrypted": 0,
            "failed":      0,
            "pushed_a":    0,
            "pushed_b":    0,
            "duration_ms": 0,
        }

    audit.append(RE_ENCRYPT_START, {
        "source":    source_server,
        "count":     total,
        "old_epoch": old_epoch,
        "new_epoch": new_epoch,
    })

    # ── Step 2: Re-encrypt all records ──
    print(f"\n[reencrypt] Step 2: Re-encrypting {total} records...")
    reencrypted, failed = reencrypt_records(
        epoch_records, old_key, new_key,
        old_epoch, new_epoch
    )

    if failed:
        print(f"[reencrypt] WARNING: {len(failed)} records failed: {failed}")

    # ── Step 3: Push re-encrypted records to Server A ──
    print(f"\n[reencrypt] Step 3: Pushing to Server A ({SERVER_A_URL})...")
    pushed_a   = 0
    isolated_a = 0
    for rec in reencrypted:
        result = _push_record(
            SERVER_A_URL,
            rec["record_id"],
            rec["nonce"],
            rec["ciphertext"],
            rec["mac_tag"],
        )
        if result == "ok":
            pushed_a += 1
        elif result == "isolated":
            isolated_a += 1
    print(f"[reencrypt] Server A: {pushed_a}/{len(reencrypted)} pushed"
          + (f" ({isolated_a} skipped — isolated)" if isolated_a else ""))

    # ── Step 4: Push re-encrypted records to Server B ──
    print(f"\n[reencrypt] Step 4: Pushing to Server B ({SERVER_B_URL})...")
    pushed_b   = 0
    isolated_b = 0
    for rec in reencrypted:
        result = _push_record(
            SERVER_B_URL,
            rec["record_id"],
            rec["nonce"],
            rec["ciphertext"],
            rec["mac_tag"],
        )
        if result == "ok":
            pushed_b += 1
        elif result == "isolated":
            isolated_b += 1
    print(f"[reencrypt] Server B: {pushed_b}/{len(reencrypted)} pushed"
          + (f" ({isolated_b} skipped — isolated)" if isolated_b else ""))

    # ── Step 5: Zero old key ──
    print(f"\n[reencrypt] Step 5: Zeroing old key K_{old_epoch}...")
    zero_key(old_key)
    print(f"[reencrypt] K_{old_epoch} erased from memory")

    # ── Step 6: Verify both servers are in sync ──
    print(f"\n[reencrypt] Step 6: Verifying server sync...")
    in_sync = _verify_sync()
    if in_sync:
        print(f"[reencrypt] Both servers are in sync at epoch {new_epoch}")
    else:
        print(f"[reencrypt] WARNING: Servers may be out of sync")

    duration_ms = round((time.time() - start_time) * 1000, 2)

    # Success if no crypto failures AND at least one live server received records.
    # Isolated-server skips (503) are NOT failures — the peer will derive the
    # same K_n+1 independently via /promote and sync records via /internal/sync.
    active_pushes = pushed_a + pushed_b
    success       = len(failed) == 0 and active_pushes > 0

    result = {
        "success":     success,
        "total":       total,
        "reencrypted": len(reencrypted),
        "failed":      len(failed),
        "pushed_a":    pushed_a,
        "pushed_b":    pushed_b,
        "in_sync":     in_sync,
        "duration_ms": duration_ms,
    }

    audit.append(RE_ENCRYPT_COMPLETE, {
        "old_epoch": old_epoch,
        "new_epoch": new_epoch,
        "total":     total,
        "success":   len(reencrypted),
        "failed":    len(failed),
        "pushed_a":  pushed_a,
        "pushed_b":  pushed_b,
        "in_sync":   in_sync,
    })

    print(f"\n[reencrypt] ── Complete in {duration_ms}ms ──")
    print(f"[reencrypt] Result: {result}")

    return result


# ─────────────────────────────────────────────
# VERIFICATION
# ─────────────────────────────────────────────

def _verify_sync() -> bool:
    """
    Check that both servers have the same record count
    and are at the same epoch.

    A lightweight sanity check — not a full diff.
    Full diff would require decrypting everything,
    which needs the key.

    Returns True if servers appear in sync.
    """
    try:
        status_a = _get(f"{SERVER_A_URL}/status")
        status_b = _get(f"{SERVER_B_URL}/status")

        epoch_a = status_a.get("epoch", -1)
        epoch_b = status_b.get("epoch", -1)
        count_a = status_a.get("record_count", -1)
        count_b = status_b.get("record_count", -1)

        print(f"[reencrypt] Server A: epoch={epoch_a} records={count_a}")
        print(f"[reencrypt] Server B: epoch={epoch_b} records={count_b}")

        return epoch_a == epoch_b and count_a == count_b

    except Exception as e:
        print(f"[reencrypt] Sync check failed: {e}")
        return False


def verify_both_servers() -> dict:
    """
    Public verification function.
    Returns status of both servers for dashboard display.
    """
    result = {
        "server_a": {},
        "server_b": {},
        "in_sync":  False,
    }

    try:
        result["server_a"] = _get(f"{SERVER_A_URL}/status")
    except Exception as e:
        result["server_a"] = {"error": str(e)}

    try:
        result["server_b"] = _get(f"{SERVER_B_URL}/status")
    except Exception as e:
        result["server_b"] = {"error": str(e)}

    a_ok = "error" not in result["server_a"]
    b_ok = "error" not in result["server_b"]

    if a_ok and b_ok:
        result["in_sync"] = (
            result["server_a"].get("epoch") ==
            result["server_b"].get("epoch")
            and
            result["server_a"].get("record_count") ==
            result["server_b"].get("record_count")
        )

    return result


# ─────────────────────────────────────────────
# STANDALONE ENTRY POINT
# ─────────────────────────────────────────────

def _parse_args():
    parser = argparse.ArgumentParser(
        description="HYDRA re-encryption orchestrator"
    )
    parser.add_argument(
        "--old-epoch", type=int, required=True,
        help="Current epoch number (records to re-encrypt)"
    )
    parser.add_argument(
        "--new-epoch", type=int, required=True,
        help="New epoch number after ratchet"
    )
    parser.add_argument(
        "--old-key", type=str, required=True,
        help="Old encryption key as hex string (32 bytes = 64 hex chars)"
    )
    parser.add_argument(
        "--new-key", type=str, required=True,
        help="New encryption key as hex string (32 bytes = 64 hex chars)"
    )
    parser.add_argument(
        "--source", type=str, default="server_a",
        choices=["server_a", "server_b"],
        help="Which server to pull records from (default: server_a)"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    try:
        old_key = bytes.fromhex(args.old_key)
        new_key = bytes.fromhex(args.new_key)
    except ValueError:
        print("ERROR: Keys must be valid hex strings")
        sys.exit(1)

    if len(old_key) != 32 or len(new_key) != 32:
        print("ERROR: Keys must be exactly 32 bytes (64 hex chars)")
        sys.exit(1)

    if args.new_epoch != args.old_epoch + 1:
        print("WARNING: new-epoch should be old-epoch + 1")

    result = run_reencryption(
        old_key       = old_key,
        new_key       = new_key,
        old_epoch     = args.old_epoch,
        new_epoch     = args.new_epoch,
        source_server = args.source,
    )

    if result["success"]:
        print(f"\nRe-encryption successful.")
        sys.exit(0)
    else:
        print(f"\nRe-encryption completed with errors.")
        sys.exit(1)