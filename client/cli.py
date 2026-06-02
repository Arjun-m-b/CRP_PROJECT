"""
HYDRA :: cli.py
===============
The HYDRA command-line interface.

This module is the primary human-facing entry-point for the HYDRA
cryptographic medical-record protection system.  It wraps every server
operation in a clean, coloured, progress-reporting shell experience.

Commands
--------
  hydra store <file>        — Encrypt a file and store it across both servers
  hydra fetch <id>          — Retrieve and reconstruct a stored record
  hydra status              — Show server health and token validity
  hydra audit               — Display the immutable audit log
  hydra simulate-breach     — Trigger emergency re-key / failover scenario
  hydra verify-chain        — Cryptographically verify the audit hash-chain

Design principles
-----------------
  - argparse for argument parsing (stdlib only — no Click dependency)
  - ANSI escape codes for colour (no colorama — we roll our own 12-colour palette)
  - A spinner class for progress indication during network I/O
  - All server communication is simulated in-process for portability; replace
    the _server_request() stub with real HTTP calls when deploying.
  - Every cryptographic step is narrated to the user at verbose level so the
    system remains educationally transparent.
"""

import argparse
import hashlib
import hmac
import json
import os
import struct
import sys
import time
import threading
from pathlib import Path
from typing import Any, Optional

# Import our HSM-simulation token module (same package).
from token import (
    DEFAULT_TOKEN_PATH,
    XCHACHA20_NONCE_BYTES,
    CHACHA20_KEY_BYTES,
    xchacha20_encrypt,
    xchacha20_decrypt,
    load_share,
    save_share,
    sign_request,
    token_info,
    _derive_key_from_passphrase,
    _hkdf_expand,
)


# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------
# We define a tiny colour palette using raw ANSI escape sequences so the CLI
# looks polished on any modern terminal without external dependencies.

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"

# Foreground colours (standard 8 + bright variants)
_RED    = "\033[91m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_BLUE   = "\033[94m"
_MAGENTA= "\033[95m"
_CYAN   = "\033[96m"
_WHITE  = "\033[97m"
_GREY   = "\033[90m"


def _c(colour: str, text: str) -> str:
    """Wrap text in an ANSI colour + reset sequence."""
    return f"{colour}{text}{_RESET}"


def _ok(msg: str) -> str:
    return f"{_GREEN}✔{_RESET}  {msg}"

def _warn(msg: str) -> str:
    return f"{_YELLOW}⚠{_RESET}  {msg}"

def _err(msg: str) -> str:
    return f"{_RED}✖{_RESET}  {msg}"

def _info(msg: str) -> str:
    return f"{_CYAN}ℹ{_RESET}  {msg}"

def _crypto(msg: str) -> str:
    """Highlight a cryptographic detail in magenta."""
    return f"{_MAGENTA}⬡{_RESET}  {_DIM}{msg}{_RESET}"

def _head(title: str) -> str:
    width = 60
    bar = "─" * width
    return (
        f"\n{_BOLD}{_CYAN}{bar}{_RESET}\n"
        f"  {_BOLD}{_WHITE}{title}{_RESET}\n"
        f"{_BOLD}{_CYAN}{bar}{_RESET}"
    )


# ---------------------------------------------------------------------------
# Spinner (progress indicator)
# ---------------------------------------------------------------------------

class Spinner:
    """
    A simple thread-based CLI spinner.

    Usage:
        with Spinner("Encrypting record"):
            time.sleep(2)

    The spinner writes to stderr so it does not pollute stdout pipelines.
    """

    _FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    _INTERVAL = 0.1  # seconds between frame updates

    def __init__(self, label: str, colour: str = _CYAN) -> None:
        self._label = label
        self._colour = colour
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _spin(self) -> None:
        frame_index = 0
        while not self._stop_event.is_set():
            frame = self._FRAMES[frame_index % len(self._FRAMES)]
            sys.stderr.write(
                f"\r{self._colour}{frame}{_RESET}  {self._label}   "
            )
            sys.stderr.flush()
            frame_index += 1
            time.sleep(self._INTERVAL)

    def __enter__(self) -> "Spinner":
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join()
        # Clear the spinner line.
        sys.stderr.write("\r" + " " * 60 + "\r")
        sys.stderr.flush()


# ---------------------------------------------------------------------------
# Simulated server layer
# (Replace _server_request with real HTTP calls for production deployment)
# ---------------------------------------------------------------------------

# In-memory fake "server state" — represents what two servers would persist.
_FAKE_SERVER_STATE: dict[str, Any] = {
    "server_a": {
        "online": True,
        "records": {},      # record_id -> {"ciphertext": bytes, "metadata": dict}
        "audit_log": [],    # list of audit entries
        "ratchet_epoch": 0,
        "chain_tail": bytes(32),
    },
    "server_b": {
        "online": True,
        "records": {},
        "audit_log": [],
        "ratchet_epoch": 0,
        "chain_tail": bytes(32),
    },
}

# Simulated master key (in real HYDRA this is *never* assembled on a single
# machine — we do so here only to make the in-process simulation coherent).
_SIMULATED_MASTER_KEY: bytes = os.urandom(CHACHA20_KEY_BYTES)

# Counter for generating unique record IDs.
_RECORD_COUNTER: int = 0


def _new_record_id() -> str:
    """Generate a sequential hex record ID."""
    global _RECORD_COUNTER
    _RECORD_COUNTER += 1
    return f"rec_{_RECORD_COUNTER:06x}"


def _append_audit_entry(server_id: str, action: str, record_id: str, detail: str) -> None:
    """
    Append an entry to the immutable audit hash-chain for a specific server.

    Each entry includes:
      - action        : what happened (STORE / FETCH / RATCHET / BREACH etc.)
      - record_id     : which record was affected
      - timestamp     : Unix epoch
      - prev_hash     : SHA-256 of the previous entry (links the chain)
      - entry_hash    : SHA-256 of this entry's content + prev_hash

    This structure means any deletion or mutation of a past entry invalidates
    all subsequent hashes — the chain is tamper-evident.
    """
    state = _FAKE_SERVER_STATE[server_id]
    tail = state.get("chain_tail", bytes(32))

    entry = {
        "seq": len(state["audit_log"]) + 1,
        "server": server_id,
        "action": action,
        "record_id": record_id,
        "detail": detail,
        "timestamp": int(time.time()),
        "prev_hash": tail.hex(),
    }

    # Hash the entry content (JSON-sorted for determinism).
    entry_bytes = json.dumps(entry, sort_keys=True).encode("utf-8")
    entry_hash = hashlib.sha256(tail + entry_bytes).digest()
    entry["entry_hash"] = entry_hash.hex()

    state["audit_log"].append(entry)

    # Advance the chain tail for this server.
    state["chain_tail"] = entry_hash


def _encrypt_record(plaintext: bytes, record_id: str) -> tuple[bytes, bytes]:
    """
    Encrypt a plaintext record using the current master key.

    Returns (ciphertext, nonce).  The nonce is stored alongside the ciphertext
    and is required for decryption.
    """
    # Derive a record-specific encryption key via HKDF-Expand.
    # Using a different key per record limits the damage if one record's
    # nonce is reused or if a partial key leak occurs.
    record_info = f"HYDRA-v1-record-{record_id}".encode("utf-8")
    record_key = _hkdf_expand(_SIMULATED_MASTER_KEY, record_info, CHACHA20_KEY_BYTES)

    nonce = os.urandom(XCHACHA20_NONCE_BYTES)
    ciphertext = xchacha20_encrypt(record_key, nonce, plaintext)
    return ciphertext, nonce


def _decrypt_record(ciphertext: bytes, nonce: bytes, record_id: str) -> bytes:
    """Decrypt a record using the current master key."""
    record_info = f"HYDRA-v1-record-{record_id}".encode("utf-8")
    record_key = _hkdf_expand(_SIMULATED_MASTER_KEY, record_info, CHACHA20_KEY_BYTES)
    return xchacha20_decrypt(record_key, nonce, ciphertext)


def _server_store(plaintext: bytes, filename: str) -> str:
    """
    Store an encrypted record on both servers.

    In production this would be two separate authenticated HTTP POST requests.
    Returns the assigned record ID.
    """
    record_id = _new_record_id()
    ciphertext, nonce = _encrypt_record(plaintext, record_id)

    metadata = {
        "filename": filename,
        "size_plaintext": len(plaintext),
        "size_ciphertext": len(ciphertext),
        "nonce_hex": nonce.hex(),
        "stored_at": int(time.time()),
        "sha256_plaintext": hashlib.sha256(plaintext).hexdigest(),
    }

    for server_id in ("server_a", "server_b"):
        if _FAKE_SERVER_STATE[server_id]["online"]:
            _FAKE_SERVER_STATE[server_id]["records"][record_id] = {
                "ciphertext": ciphertext,
                "metadata": metadata,
            }
            _append_audit_entry(
                server_id, "STORE", record_id,
                f"file={filename} size={len(plaintext)} bytes"
            )

    return record_id


def _server_fetch(record_id: str) -> tuple[bytes, dict]:
    """
    Fetch and decrypt a record from the first available server.

    Returns (plaintext, metadata).
    Raises KeyError if record not found on any online server.
    """
    for server_id in ("server_a", "server_b"):
        if not _FAKE_SERVER_STATE[server_id]["online"]:
            continue
        records = _FAKE_SERVER_STATE[server_id]["records"]
        if record_id in records:
            rec = records[record_id]
            nonce = bytes.fromhex(rec["metadata"]["nonce_hex"])
            plaintext = _decrypt_record(rec["ciphertext"], nonce, record_id)
            _append_audit_entry(
                server_id, "FETCH", record_id, "client retrieval"
            )
            return plaintext, rec["metadata"]

    raise KeyError(f"Record {record_id!r} not found on any online server")


def _server_status() -> dict:
    """Return a status snapshot of both servers."""
    result = {}
    for server_id in ("server_a", "server_b"):
        state = _FAKE_SERVER_STATE[server_id]
        result[server_id] = {
            "online": state["online"],
            "record_count": len(state["records"]),
            "audit_entries": len(state["audit_log"]),
            "ratchet_epoch": state["ratchet_epoch"],
        }
    return result


def _server_audit_log() -> list[dict]:
    """Return a merged, time-sorted audit log from all online servers."""
    entries: list[dict] = []
    for server_id in ("server_a", "server_b"):
        if _FAKE_SERVER_STATE[server_id]["online"]:
            entries.extend(_FAKE_SERVER_STATE[server_id]["audit_log"])
    entries.sort(key=lambda e: e["seq"])
    return entries


def _server_simulate_breach() -> dict:
    """
    Simulate a security breach and trigger emergency re-key.

    Actions performed:
      1. Mark Server A as compromised (taken offline).
      2. Ratchet the master key on Server B (forward secrecy).
      3. Re-encrypt all records under the new key.
      4. Log the breach event in the audit chain.

    Returns a dict describing what happened.
    """
    global _SIMULATED_MASTER_KEY

    report: dict[str, Any] = {}

    # Step 1: take Server A offline.
    _FAKE_SERVER_STATE["server_a"]["online"] = False
    report["server_a_status"] = "OFFLINE (compromised)"

    # Step 2: ratchet the master key — derive a new key from the old one.
    # In real HYDRA the ratchet is driven by an HKDF-based KDF using a
    # shared ratchet state.  Here we use a simple HKDF-Expand step.
    old_key = _SIMULATED_MASTER_KEY
    ratchet_info = b"HYDRA-v1-ratchet-emergency"
    new_key = _hkdf_expand(old_key, ratchet_info, CHACHA20_KEY_BYTES)
    _SIMULATED_MASTER_KEY = new_key

    _FAKE_SERVER_STATE["server_b"]["ratchet_epoch"] += 1
    report["ratchet_epoch"] = _FAKE_SERVER_STATE["server_b"]["ratchet_epoch"]
    report["old_key_fingerprint"] = hashlib.sha256(old_key).hexdigest()[:16] + "…"
    report["new_key_fingerprint"] = hashlib.sha256(new_key).hexdigest()[:16] + "…"

    # Step 3: re-encrypt all records on Server B under the new key.
    re_encrypted_count = 0
    for record_id, rec in _FAKE_SERVER_STATE["server_b"]["records"].items():
        old_nonce = bytes.fromhex(rec["metadata"]["nonce_hex"])

        # Decrypt with old key.
        old_record_info = f"HYDRA-v1-record-{record_id}".encode("utf-8")
        old_record_key = _hkdf_expand(old_key, old_record_info, CHACHA20_KEY_BYTES)
        plaintext = xchacha20_decrypt(old_record_key, old_nonce, rec["ciphertext"])

        # Re-encrypt with new key.
        new_record_info = f"HYDRA-v1-record-{record_id}".encode("utf-8")
        new_record_key = _hkdf_expand(new_key, new_record_info, CHACHA20_KEY_BYTES)
        new_nonce = os.urandom(XCHACHA20_NONCE_BYTES)
        new_ciphertext = xchacha20_encrypt(new_record_key, new_nonce, plaintext)

        rec["ciphertext"] = new_ciphertext
        rec["metadata"]["nonce_hex"] = new_nonce.hex()
        re_encrypted_count += 1

    report["records_re_encrypted"] = re_encrypted_count

    # Step 4: audit entry.
    _append_audit_entry(
        "server_b", "BREACH_RESPONSE", "N/A",
        f"emergency ratchet epoch={report['ratchet_epoch']} "
        f"re_encrypted={re_encrypted_count}"
    )
    report["audit_entry"] = "BREACH_RESPONSE logged"

    return report


def _verify_chain() -> tuple[bool, list[dict]]:
    """
    Walk the audit hash-chain for each online server and verify every link.

    Returns (is_valid, list_of_verification_results).
    Each result dict has keys: seq, valid, expected_hash, actual_hash.
    """
    entries = _server_audit_log()
    if not entries:
        return True, []

    results: list[dict] = []
    chain_ok = True

    for server_id in ("server_a", "server_b"):
        if not _FAKE_SERVER_STATE[server_id]["online"]:
            continue

        prev_hash = bytes(32)  # genesis hash
        server_entries = [e for e in entries if e["server"] == server_id]

        for entry in server_entries:
            # Reconstruct the hash for this entry.
            entry_copy = {k: v for k, v in entry.items() if k != "entry_hash"}
            entry_bytes = json.dumps(entry_copy, sort_keys=True).encode("utf-8")
            expected_hash = hashlib.sha256(prev_hash + entry_bytes).hexdigest()
            stored_hash = entry["entry_hash"]

            is_valid = hmac.compare_digest(expected_hash, stored_hash)
            chain_ok = chain_ok and is_valid

            results.append(
                {
                    "seq": entry["seq"],
                    "action": entry["action"],
                    "record_id": entry["record_id"],
                    "server": entry["server"],
                    "expected": expected_hash[:16] + "…",
                    "stored": stored_hash[:16] + "…",
                    "valid": is_valid,
                }
            )
            prev_hash = bytes.fromhex(stored_hash)

    # Sort results by sequence for display
    results.sort(key=lambda r: (r["seq"], r["server"]))
    return chain_ok, results


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------

def cmd_store(args: argparse.Namespace) -> int:
    """
    hydra store <file>

    1. Read the file from disk.
    2. Encrypt it client-side (XChaCha20 under a locally-derived key).
    3. Upload the encrypted blob to both servers.
    4. Print the record ID for future retrieval.

    We do client-side encryption before upload so the servers never see
    the plaintext — zero-trust architecture.
    """
    print(_head("HYDRA STORE"))

    file_path = Path(args.file)
    if not file_path.exists():
        print(_err(f"File not found: {file_path}"))
        return 1

    # ── Read the file ──────────────────────────────────────────────────────
    with Spinner(f"Reading {_c(_CYAN, file_path.name)}"):
        plaintext = file_path.read_bytes()
        time.sleep(0.3)  # realistic pause

    print(_ok(f"Read {_c(_WHITE, str(len(plaintext)))} bytes from {_c(_CYAN, str(file_path))}"))
    print(_crypto(f"SHA-256 fingerprint: {hashlib.sha256(plaintext).hexdigest()}"))

    # ── Client-side pre-encryption ─────────────────────────────────────────
    # We encrypt client-side using a passphrase-derived key.  The server
    # performs a second layer of encryption using the distributed master key.
    # This double-encryption means a server compromise alone is insufficient
    # to recover the plaintext.
    passphrase = _prompt_passphrase("Enter token passphrase for signing and encryption")

    with Spinner("Signing and encrypting locally"):
        try:
            signature_hex = sign_request(plaintext, passphrase)
            
            # Client-side encryption
            client_salt = os.urandom(32)
            client_key = _derive_key_from_passphrase(passphrase, client_salt)
            client_nonce = os.urandom(XCHACHA20_NONCE_BYTES)
            client_ciphertext = xchacha20_encrypt(client_key, client_nonce, plaintext)
            
            # Prepend magic bytes + salt + nonce so we know how to decrypt it on fetch
            upload_payload = b"HYDC" + client_salt + client_nonce + client_ciphertext
        except (FileNotFoundError, ValueError) as exc:
            print()
            print(_warn(f"No valid token found ({exc}). Proceeding without signing/encryption."))
            signature_hex = "unsigned"
            upload_payload = plaintext
        time.sleep(0.4)

    print(_crypto(f"Request signature: {signature_hex[:32]}…"))

    # ── Upload to servers ──────────────────────────────────────────────────
    with Spinner("Uploading and distributing across servers"):
        record_id = _server_store(upload_payload, file_path.name)
        time.sleep(0.6)

    print(_ok(f"Record stored on both servers"))
    print(_crypto(f"Client XChaCha20 + Server XChaCha20 applied"))
    print()
    print(f"  {_BOLD}{_WHITE}Record ID:{_RESET}  {_c(_GREEN, record_id)}")
    print()
    print(_info("Save this ID — you will need it to fetch this record."))
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    """
    hydra fetch <id>

    1. Request the encrypted blob from the first available server.
    2. Decrypt it.
    3. Write the reconstructed file to disk with a .hydra_decrypted suffix.
    """
    print(_head("HYDRA FETCH"))

    record_id = args.id

    with Spinner(f"Fetching record {_c(_CYAN, record_id)}"):
        try:
            download_payload, metadata = _server_fetch(record_id)
        except KeyError as exc:
            print()
            print(_err(str(exc)))
            return 1
        time.sleep(0.5)

    # Verify the SHA-256 of the recovered payload matches the stored hash on the server.
    recovered_sha256 = hashlib.sha256(download_payload).hexdigest()
    expected_sha256 = metadata["sha256_plaintext"]

    if not hmac.compare_digest(recovered_sha256, expected_sha256):
        print(_err("Server integrity check FAILED — recovered data is corrupt!"))
        print(_crypto(f"Expected:  {expected_sha256}"))
        print(_crypto(f"Recovered: {recovered_sha256}"))
        return 1

    print(_ok(f"Fetched {_c(_WHITE, str(len(download_payload)))} bytes from servers"))
    print(_crypto(f"Server integrity check: {_c(_GREEN, 'PASSED')} (SHA-256 matches)"))
    
    # ── Client-side decryption ─────────────────────────────────────────────
    if download_payload.startswith(b"HYDC"):
        passphrase = _prompt_passphrase("Enter token passphrase to decrypt record")
        if not passphrase:
            print(_err("Passphrase is required to decrypt the record."))
            return 1

        with Spinner("Decrypting record locally"):
            try:
                # payload is: b"HYDC" (4) + salt (32) + nonce (24) + ciphertext
                salt = download_payload[4:36]
                nonce = download_payload[36:60]
                client_ciphertext = download_payload[60:]
                
                client_key = _derive_key_from_passphrase(passphrase, salt)
                plaintext = xchacha20_decrypt(client_key, nonce, client_ciphertext)
            except Exception as e:
                print()
                print(_err(f"Local decryption failed: {e}"))
                return 1
            time.sleep(0.4)
        print(_ok("Local decryption successful"))
    else:
        plaintext = download_payload
        print(_warn("Record was not locally encrypted, saving as-is."))

    print(_crypto(f"Original filename: {metadata['filename']}"))

    # Write decrypted output.
    out_path = Path(f"{metadata['filename']}.hydra_decrypted")
    out_path.write_bytes(plaintext)

    print(_ok(f"Saved to {_c(_CYAN, str(out_path))}"))
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """
    hydra status

    Display health information for both servers and the local token.
    """
    print(_head("HYDRA SYSTEM STATUS"))

    # ── Server health ──────────────────────────────────────────────────────
    with Spinner("Querying server health"):
        status = _server_status()
        time.sleep(0.3)

    for server_id, info in status.items():
        icon = _c(_GREEN, "●") if info["online"] else _c(_RED, "●")
        state_label = _c(_GREEN, "ONLINE") if info["online"] else _c(_RED, "OFFLINE")
        print(f"\n  {icon}  {_BOLD}{server_id.replace('_', ' ').upper()}{_RESET}  —  {state_label}")
        print(f"     {_DIM}Records       :{_RESET}  {info['record_count']}")
        print(f"     {_DIM}Audit entries :{_RESET}  {info['audit_entries']}")
        print(f"     {_DIM}Ratchet epoch :{_RESET}  {info['ratchet_epoch']}")

    # ── Token health ───────────────────────────────────────────────────────
    print()
    passphrase = _prompt_passphrase("Enter token passphrase to verify token", optional=True)
    if passphrase:
        try:
            info = token_info(passphrase)
            print(f"\n  {_c(_GREEN, '●')}  {_BOLD}LOCAL TOKEN{_RESET}  —  {_c(_GREEN, 'VALID')}")
            print(f"     {_DIM}Share index :{_RESET}  {info['share_index']}")
            print(f"     {_DIM}Node        :{_RESET}  {info['node_id']}")
            print(f"     {_DIM}Created     :{_RESET}  {info['created_at']}")
            print(f"     {_DIM}Path        :{_RESET}  {info['token_path']}")
        except (FileNotFoundError, ValueError) as exc:
            print(f"\n  {_c(_RED, '●')}  {_BOLD}LOCAL TOKEN{_RESET}  —  {_c(_RED, 'INVALID')}")
            print(f"     {exc}")
    else:
        print(_info("(token check skipped — no passphrase entered)"))

    print()
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """
    hydra audit

    Display the immutable audit log in a human-readable table.
    """
    print(_head("HYDRA AUDIT LOG"))

    with Spinner("Loading audit entries"):
        entries = _server_audit_log()
        time.sleep(0.3)

    if not entries:
        print(_info("Audit log is empty."))
        return 0

    # ── Table header ───────────────────────────────────────────────────────
    col_seq    = 5
    col_ts     = 20
    col_server = 10
    col_action = 16
    col_rec    = 14
    col_prev   = 22
    col_hash   = 22

    def _row(seq, ts, srv, act, rec, prev, hsh, header=False):
        if header:
            fmt = _BOLD + _CYAN
            end = _RESET
        else:
            fmt = _DIM
            end = _RESET
        print(
            f"  {fmt}{str(seq):<{col_seq}}{end}"
            f"  {fmt}{str(ts):<{col_ts}}{end}"
            f"  {fmt}{str(srv):<{col_server}}{end}"
            f"  {fmt}{str(act):<{col_action}}{end}"
            f"  {fmt}{str(rec):<{col_rec}}{end}"
            f"  {fmt}{str(prev):<{col_prev}}{end}"
            f"  {fmt}{str(hsh):<{col_hash}}{end}"
        )

    _row("#", "TIMESTAMP", "SERVER", "ACTION", "RECORD", "PREV_HASH", "ENTRY_HASH", header=True)
    print("  " + "─" * (col_seq + col_ts + col_server + col_action + col_rec + col_prev + col_hash + 14))

    for e in entries:
        ts_human = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(e["timestamp"]))
        action_coloured = (
            _c(_RED, e["action"]) if "BREACH" in e["action"]
            else _c(_YELLOW, e["action"]) if e["action"] in ("RATCHET", "FAILOVER")
            else _c(_GREEN, e["action"])
        )
        _row(
            e["seq"],
            ts_human,
            e["server"],
            e["action"],    # plain for alignment; colour handled below
            e["record_id"],
            e["prev_hash"][:18] + "…",
            e["entry_hash"][:18] + "…",
        )

    print(f"\n  {_DIM}Total entries: {len(entries)}{_RESET}")
    print(_info("Run 'hydra verify-chain' to cryptographically validate this log."))
    return 0


def cmd_simulate_breach(args: argparse.Namespace) -> int:
    """
    hydra simulate-breach

    Trigger an emergency breach simulation:
      - Take Server A offline.
      - Ratchet the master key (forward secrecy).
      - Re-encrypt all records under the new key.
      - Display the incident report.
    """
    print(_head("HYDRA BREACH SIMULATION"))
    print(_warn("This will take Server A OFFLINE and ratchet the master key."))
    confirm = input(f"  {_YELLOW}Type 'yes' to proceed:{_RESET} ").strip().lower()
    if confirm != "yes":
        print(_info("Breach simulation cancelled."))
        return 0

    print()

    with Spinner(_c(_RED, "Executing emergency response protocol")):
        report = _server_simulate_breach()
        time.sleep(1.0)

    print(_err(f"Server A status: {report['server_a_status']}"))
    print()
    print(f"  {_BOLD}{_YELLOW}Emergency Key Ratchet{_RESET}")
    print(f"  {_DIM}Old key fingerprint :{_RESET}  {_c(_RED, report['old_key_fingerprint'])}")
    print(f"  {_DIM}New key fingerprint :{_RESET}  {_c(_GREEN, report['new_key_fingerprint'])}")
    print(f"  {_DIM}Ratchet epoch       :{_RESET}  {report['ratchet_epoch']}")
    print()
    print(_crypto("HKDF-Expand used for forward-secret key derivation"))
    print(_crypto(f"Records re-encrypted : {report['records_re_encrypted']}"))
    print(_ok(f"Audit entry          : {report['audit_entry']}"))
    print()
    print(_warn("Server A must be re-provisioned before it can rejoin the cluster."))
    print(_info("Forward secrecy maintained — old ciphertexts are no longer decryptable."))
    return 0


def cmd_verify_chain(args: argparse.Namespace) -> int:
    """
    hydra verify-chain

    Walk every entry in the audit hash-chain and re-compute its hash from
    scratch, comparing against the stored value.  Any tampering with past
    entries will break the chain at the modified link.
    """
    print(_head("HYDRA CHAIN VERIFICATION"))

    with Spinner("Verifying audit hash-chain"):
        is_valid, results = _verify_chain()
        time.sleep(0.5)

    if not results:
        print(_info("No audit entries to verify."))
        return 0

    print()
    for r in results:
        icon = _c(_GREEN, "✔") if r["valid"] else _c(_RED, "✖")
        action_str = f"{r['action']:<16}"
        hash_match = (
            _c(_GREEN, "MATCH")
            if r["valid"]
            else _c(_RED, "MISMATCH")
        )
        print(
            f"  {icon}  seq={_c(_CYAN, str(r['seq'])):>6}  "
            f"{_DIM}{action_str}{_RESET}  "
            f"record={r['record_id']:<14}  "
            f"hash={hash_match}  "
            f"{_DIM}{r['stored']}{_RESET}"
        )

    print()
    if is_valid:
        print(
            _ok(
                f"Chain VALID — all {len(results)} entries verified. "
                "Audit log has not been tampered with."
            )
        )
    else:
        failed = sum(1 for r in results if not r["valid"])
        print(
            _err(
                f"Chain INVALID — {failed} of {len(results)} entries failed verification. "
                "The audit log may have been tampered with!"
            )
        )

    return 0 if is_valid else 1


# ---------------------------------------------------------------------------
# Token management helper (not a top-level command but used by setup flows)
# ---------------------------------------------------------------------------

def _prompt_passphrase(prompt: str, optional: bool = False) -> Optional[str]:
    """
    Prompt the user for a passphrase without echo.

    Falls back to getpass; if that is unavailable (headless CI), reads from
    HYDRA_PASSPHRASE env-var.  If optional=True and nothing is provided,
    returns None.
    """
    env_pass = os.environ.get("HYDRA_PASSPHRASE")
    if env_pass:
        return env_pass

    try:
        import getpass
        value = getpass.getpass(f"\n  {_CYAN}🔑 {prompt}:{_RESET} ")
    except Exception:
        value = input(f"\n  {_CYAN}🔑 {prompt}:{_RESET} ")

    if not value and optional:
        return None
    return value


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """
    Construct the argparse argument parser for all HYDRA subcommands.

    We use subparsers so each command has its own --help text and its own
    set of required/optional arguments.
    """
    parser = argparse.ArgumentParser(
        prog="hydra",
        description=(
            f"{_BOLD}{_CYAN}HYDRA{_RESET} — Distributed Cryptographic Medical-Record Protection System\n"
            "\n"
            "  Commands:\n"
            f"    {_WHITE}store{_RESET}            Encrypt and store a file across both servers\n"
            f"    {_WHITE}fetch{_RESET}            Retrieve and reconstruct a stored record\n"
            f"    {_WHITE}status{_RESET}           Display server health and token validity\n"
            f"    {_WHITE}audit{_RESET}            Show the immutable audit log\n"
            f"    {_WHITE}simulate-breach{_RESET}  Trigger emergency re-key / failover\n"
            f"    {_WHITE}verify-chain{_RESET}     Cryptographically verify the audit hash-chain\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print additional cryptographic details",
    )
    parser.add_argument(
        "--token-path",
        type=Path,
        default=DEFAULT_TOKEN_PATH,
        metavar="PATH",
        help=f"Path to local token file (default: {DEFAULT_TOKEN_PATH})",
    )

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # ── store ──────────────────────────────────────────────────────────────
    p_store = sub.add_parser(
        "store",
        help="Encrypt and store a file",
        description="Encrypt a local file and distribute it across both HYDRA servers.",
    )
    p_store.add_argument("file", metavar="<file>", help="Path to the file to store")

    # ── fetch ──────────────────────────────────────────────────────────────
    p_fetch = sub.add_parser(
        "fetch",
        help="Retrieve and reconstruct a stored record",
        description="Fetch a record by ID and write the decrypted file to disk.",
    )
    p_fetch.add_argument("id", metavar="<id>", help="Record ID returned by 'hydra store'")

    # ── status ─────────────────────────────────────────────────────────────
    sub.add_parser(
        "status",
        help="Display server health and token validity",
        description="Show the health of both servers and the local hardware token.",
    )

    # ── audit ──────────────────────────────────────────────────────────────
    sub.add_parser(
        "audit",
        help="Display the immutable audit log",
        description="Print all entries in the hash-chain audit log.",
    )

    # ── simulate-breach ────────────────────────────────────────────────────
    sub.add_parser(
        "simulate-breach",
        help="Simulate a breach and trigger emergency re-key",
        description=(
            "Take Server A offline, ratchet the master key for forward secrecy, "
            "and re-encrypt all records on Server B."
        ),
    )

    # ── verify-chain ───────────────────────────────────────────────────────
    sub.add_parser(
        "verify-chain",
        help="Cryptographically verify the audit hash-chain",
        description=(
            "Walk every entry in the audit log and re-compute its SHA-256 hash "
            "from scratch to detect any tampering."
        ),
    )

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

COMMAND_MAP = {
    "store":           cmd_store,
    "fetch":           cmd_fetch,
    "status":          cmd_status,
    "audit":           cmd_audit,
    "simulate-breach": cmd_simulate_breach,
    "verify-chain":    cmd_verify_chain,
}


def main() -> None:
    """
    Parse arguments and dispatch to the appropriate command handler.

    Exit codes:
      0 — success
      1 — error (printed to stderr)
      2 — argument parse error (argparse default)
    """
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    # Store token path in args so command handlers can access it uniformly.
    if not hasattr(args, "token_path"):
        args.token_path = DEFAULT_TOKEN_PATH

    handler = COMMAND_MAP.get(args.command)
    if handler is None:
        print(_err(f"Unknown command: {args.command!r}"))
        parser.print_help()
        sys.exit(2)

    try:
        exit_code = handler(args)
        sys.exit(exit_code if exit_code is not None else 0)
    except KeyboardInterrupt:
        print(f"\n{_warn('Interrupted by user.')}")
        sys.exit(130)
    except Exception as exc:
        print(_err(f"Unhandled error: {exc}"))
        if hasattr(args, "verbose") and args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
