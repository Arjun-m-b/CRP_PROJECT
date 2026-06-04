# server_b/app.py
# HYDRA Server B — Standby server

import sys
import os
import time
import threading
import base64
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding='utf-8')

from reencrypt import run_reencryption

from flask import Flask, request, jsonify
import requests as http

from core.xchacha20 import encrypt, decrypt, generate_key, generate_nonce, clear_nonce_registry
from core.shamir    import reconstruct_key, deserialize_share, encode_share_for_server
from core.hkdf      import ratchet, zero_key, derive_subkeys
from core.audit     import (
    AuditLog,
    SERVER_STARTED, KEY_CEREMONY, SHARE_ISSUED,
    RATCHET_TRIGGERED, RATCHET_COMPLETE,
    FAILOVER_INITIATED, FAILOVER_COMPLETE,
    RE_ENCRYPT_START, RE_ENCRYPT_COMPLETE,
    ZK_PROOF_PASSED, ZK_PROOF_FAILED,
    RECORD_STORED, RECORD_FETCHED,
    BREACH_SCORE_HIGH, SERVER_ISOLATED
)
from server_b.breach import BreachDetector, THETA
from server_b.store  import EncryptedStore


# ─────────────────────────────────────────────
# CONFIG — everything that differs from Server A
# ─────────────────────────────────────────────

PEER_URL    = "http://127.0.0.1:5001"   # Server A
SERVER_ID   = "server_b"
SERVER_PORT = 5002
AUDIT_PATH  = os.path.join(os.path.dirname(__file__), "audit_b.json")


# ─────────────────────────────────────────────
# APP + STATE
# ─────────────────────────────────────────────

app = Flask(__name__)


@app.after_request
def _cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response


_lock = threading.Lock()

state = {
    "current_key":  None,
    "epoch":        0,
    "my_share":     None,
    "role":         "standby",    # B starts as STANDBY
    "ratcheting":   False,
    "isolated":     False,
    "started_at":   time.time(),
}

detector = BreachDetector()
store    = EncryptedStore()
audit    = AuditLog(AUDIT_PATH)


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _ok(data: dict = None, status: int = 200):
    payload = {"status": "ok"}
    if data:
        payload.update(data)
    return jsonify(payload), status


def _err(message: str, status: int = 400):
    return jsonify({"status": "error", "message": message}), status


def _get_request_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _check_breach(ip: str):
    """
    Record request and check breach score.
    If score >= THETA, trigger ratchet in background.
    """
    detector.record_request(ip)
    score = detector.compute(ip)

    if score >= THETA and not state["ratcheting"] and not state["isolated"]:
        audit.append(BREACH_SCORE_HIGH, {
            "score":  score,
            "ip":     ip,
            "epoch":  state["epoch"],
            "server": SERVER_ID,
        })
        t = threading.Thread(target=_trigger_ratchet, daemon=True)
        t.start()


def _notify_peer(endpoint: str, payload: dict) -> bool:
    try:
        resp = http.post(
            f"{PEER_URL}{endpoint}",
            json=payload,
            timeout=3
        )
        return resp.status_code == 200
    except Exception:
        return False


# ─────────────────────────────────────────────
# RATCHET
# ─────────────────────────────────────────────

def _re_encrypt_all(old_key: bytes, new_key: bytes,
                    old_epoch: int, new_epoch: int):
    """
    Decrypt all records at old_epoch, re-encrypt under new_epoch.
    Every record gets a fresh nonce.
    """
    records = store.get_all_by_epoch(old_epoch)

    audit.append(RE_ENCRYPT_START, {
        "count":     len(records),
        "old_epoch": old_epoch,
        "new_epoch": new_epoch,
    })

    print(f"[{SERVER_ID}] Re-encrypting {len(records)} records...")
    failed = 0

    for rec in records:
        try:
            plaintext = decrypt(
                old_key,
                rec["nonce"],
                rec["ciphertext"],
                rec["mac_tag"]
            )
            new_nonce, new_ct, new_tag = encrypt(new_key, plaintext)
            store.update(
                rec["id"],
                new_epoch=new_epoch,
                new_nonce=new_nonce,
                new_ciphertext=new_ct,
                new_mac_tag=new_tag,
            )
        except Exception as e:
            print(f"[{SERVER_ID}] Re-encrypt failed for {rec['id']}: {e}")
            failed += 1

    audit.append(RE_ENCRYPT_COMPLETE, {
        "total":     len(records),
        "success":   len(records) - failed,
        "failed":    failed,
        "new_epoch": new_epoch,
    })

    print(f"[{SERVER_ID}] Re-encryption done. "
          f"{len(records) - failed}/{len(records)} succeeded.")


def _trigger_ratchet():
    """
    Full ratchet sequence for Server B.

    Steps:
        1. Derive K_n+1 from K_n
        2. Zero K_n immediately
        3. Re-encrypt all records under K_n+1
        4. Server B PROMOTES itself to primary
        5. Notify Server A to ISOLATE itself
    """
    with _lock:
        if state["ratcheting"] or state["isolated"]:
            return
        state["ratcheting"] = True

    old_epoch = state["epoch"]
    new_epoch = old_epoch + 1

    audit.append(RATCHET_TRIGGERED, {
        "old_epoch": old_epoch,
        "new_epoch": new_epoch,
        "server":    SERVER_ID,
        "score":     detector.current_score,
    })

    print(f"[{SERVER_ID}] RATCHET TRIGGERED — "
          f"epoch {old_epoch} -> {new_epoch}")

    old_key = state["current_key"]
    if old_key is None:
        print(f"[{SERVER_ID}] ERROR: no key to ratchet")
        with _lock:
            state["ratcheting"] = False
        return

    # Derive new key — keep a copy of old_key for re-encryption
    old_key_copy = bytes(old_key)  # snapshot before zeroing
    new_key = ratchet(old_key, epoch=new_epoch, server_id=SERVER_ID)
    # Clear nonce registry for the old key — it's being retired
    clear_nonce_registry(old_key)
    zero_key(old_key)
    print(f"[{SERVER_ID}] K_{old_epoch} erased")

    # Re-encrypt all records using the saved copy
    result = run_reencryption(
    old_key       = old_key_copy,
    new_key       = new_key,
    old_epoch     = old_epoch,
    new_epoch     = new_epoch,
    source_server = "server_b"   
    )

    if not result["success"]:
        print(f"[{SERVER_ID}] WARNING: Re-encryption had errors: {result}")

    # Update state
    with _lock:
        state["current_key"] = new_key
        state["epoch"]       = new_epoch
        state["ratcheting"]  = False

    audit.append(RATCHET_COMPLETE, {
        "new_epoch": new_epoch,
        "server":    SERVER_ID,
    })

    # ── FAILOVER LOGIC ──
    current_role = state["role"]
    
    if current_role == "primary":
        print(f"[{SERVER_ID}] Notifying Server A to promote...")
        promoted = _notify_peer("/promote", {
            "new_epoch":   new_epoch,
            "from_server": SERVER_ID,
        })

        if promoted:
            audit.append(FAILOVER_INITIATED, {
                "new_primary": "server_a",
                "epoch":       new_epoch,
            })
            print(f"[{SERVER_ID}] Server A notified")
        else:
            print(f"[{SERVER_ID}] WARNING: Could not reach Server A")

        with _lock:
            state["isolated"] = True
            state["role"]     = "standby"

        audit.append(SERVER_ISOLATED, {
            "server": SERVER_ID,
            "epoch":  new_epoch,
            "reason": "breach detected — ratchet complete",
        })
        print(f"[{SERVER_ID}] Isolated. Server A is now primary.")
    else:
        with _lock:
            state["role"]     = "primary"
            state["isolated"] = False

        audit.append(FAILOVER_COMPLETE, {
            "new_primary": SERVER_ID,
            "epoch":       new_epoch,
        })
        print(f"[{SERVER_ID}] PROMOTED to primary — epoch {new_epoch}")

        print(f"[{SERVER_ID}] Notifying Server A to isolate...")
        _notify_peer("/isolate", {
            "new_epoch":   new_epoch,
            "from_server": SERVER_ID,
        })

    detector.reset()


# ─────────────────────────────────────────────
# PEER RECORD SYNC (post-promotion)
# ─────────────────────────────────────────────

def _sync_records_from_peer(epoch: int):
    """
    Pull re-encrypted records from the isolated peer after promotion.

    After a failover the peer holds epoch-N+1 records that were never
    pushed to us (our /store was returning 503 while we were isolated).
    Pull them now via /internal/sync which bypasses the peer’s isolation.
    """
    print(f"[{SERVER_ID}] Syncing records at epoch {epoch} from peer...")
    try:
        resp = http.get(
            f"{PEER_URL}/internal/sync",
            params={"epoch": epoch},
            timeout=10,
        )
        if resp.status_code != 200:
            print(f"[{SERVER_ID}] Peer sync returned {resp.status_code} — skipping")
            return

        records = resp.json().get("records", [])
        print(f"[{SERVER_ID}] Pulling {len(records)} records from peer at epoch {epoch}")

        synced = 0
        for rec in records:
            try:
                ok = store.save(
                    rec["record_id"],
                    epoch=rec["epoch"],
                    nonce=bytes.fromhex(rec["nonce"]),
                    ciphertext=bytes.fromhex(rec["ciphertext"]),
                    mac_tag=bytes.fromhex(rec["mac_tag"]),
                )
                if ok:
                    synced += 1
            except Exception as exc:
                print(f"[{SERVER_ID}] Sync record error: {exc}")

        print(f"[{SERVER_ID}] Sync complete — {synced}/{len(records)} records")

    except Exception as e:
        print(f"[{SERVER_ID}] Peer sync failed: {e}")


# ─────────────────────────────────────────────
# HEARTBEAT THREAD
# ─────────────────────────────────────────────

def _heartbeat_loop():
    while True:
        time.sleep(5)
        try:
            resp = http.post(
                f"{PEER_URL}/heartbeat",
                json={
                    "from":  SERVER_ID,
                    "score": detector.current_score,
                    "epoch": state["epoch"],
                    "role":  state["role"],
                },
                timeout=3
            )
            if resp.status_code == 200:
                data = resp.json()
                detector.update_peer_score(data.get("score", 0.0))
        except Exception:
            pass


# ─────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────

@app.route("/status", methods=["GET"])
def status():
    ip    = _get_request_ip()
    score = detector.compute(ip)
    return _ok({
        "server":         SERVER_ID,
        "role":           state["role"],
        "epoch":          state["epoch"],
        "score":          score,
        "is_breach":      score >= THETA,
        "isolated":       state["isolated"],
        "ratcheting":     state["ratcheting"],
        "initialised":    state["current_key"] is not None,
        "record_count":   store.count(),
        "uptime_seconds": round(time.time() - state["started_at"], 1),
    })


@app.route("/init", methods=["POST"])
def init():
    ip = _get_request_ip()
    _check_breach(ip)

    data = request.get_json()
    if not data:
        return _err("No JSON body")

    for field in ["key_hex", "share_x", "share_y"]:
        if field not in data:
            return _err(f"Missing field: {field}")

    try:
        key   = bytes.fromhex(data["key_hex"])
        epoch = int(data.get("epoch", 1))
        share = (int(data["share_x"]),
                 int(data["share_y"], 16))
    except Exception as e:
        return _err(f"Invalid data: {e}")

    if len(key) != 32:
        return _err("Key must be 32 bytes")

    with _lock:
        state["current_key"] = key
        state["epoch"]       = epoch
        state["my_share"]    = share
        state["isolated"]    = False
        state["role"]        = "standby"    # B always inits as standby

    audit.append(KEY_CEREMONY, {
        "server":  SERVER_ID,
        "epoch":   epoch,
        "share_x": share[0],
    })

    audit.append(SHARE_ISSUED, {
        "recipient": SERVER_ID,
        "share_x":   share[0],
        "epoch":     epoch,
    })

    print(f"[{SERVER_ID}] Initialised — epoch={epoch}")
    return _ok({"epoch": epoch, "server": SERVER_ID})


@app.route("/store", methods=["POST"])
def store_record():
    ip = _get_request_ip()
    _check_breach(ip)

    if state["isolated"]:
        return _err("Server B is isolated", 503)
    if state["current_key"] is None:
        return _err("Server not initialised", 503)

    data = request.get_json()
    if not data:
        return _err("No JSON body")

    for field in ["record_id", "nonce", "ciphertext", "mac_tag"]:
        if field not in data:
            return _err(f"Missing field: {field}")

    try:
        record_id  = data["record_id"]
        nonce      = bytes.fromhex(data["nonce"])
        ciphertext = bytes.fromhex(data["ciphertext"])
        mac_tag    = bytes.fromhex(data["mac_tag"])
    except Exception as e:
        return _err(f"Invalid hex: {e}")

    if len(nonce) != 24:
        return _err("Nonce must be 24 bytes")
    if len(mac_tag) != 32:
        return _err("MAC tag must be 32 bytes")

    ok = store.save(
        record_id,
        epoch=state["epoch"],
        nonce=nonce,
        ciphertext=ciphertext,
        mac_tag=mac_tag,
    )

    if not ok:
        return _err("Failed to save record", 500)

    audit.append(RECORD_STORED, {
        "record_id": record_id,
        "epoch":     state["epoch"],
        "server":    SERVER_ID,
    })

    # ── SERVER B SPECIFIC: only mirror if primary ──
    # Prevents infinite mirror loop between A and B
    if state["role"] == "primary":
        threading.Thread(
            target=_notify_peer,
            args=["/store", data],
            daemon=True
        ).start()

    return _ok({"record_id": record_id, "epoch": state["epoch"]})


@app.route("/store_payload", methods=["POST"])
def store_payload():
    ip = _get_request_ip()
    _check_breach(ip)

    if state["isolated"]:
        return _err("Server B is isolated", 503)
    if state["current_key"] is None:
        return _err("Server not initialised", 503)

    data = request.get_json()
    if not data or "payload_b64" not in data:
        return _err("Missing payload_b64")

    try:
        plaintext = base64.b64decode(data["payload_b64"])
    except Exception as e:
        return _err(f"Invalid base64: {e}")

    # Generate a new record ID
    record_id = f"rec_{os.urandom(4).hex()}"

    # Encrypt the payload with the server's master key
    nonce, ciphertext, mac_tag = encrypt(state["current_key"], plaintext)

    ok = store.save(
        record_id,
        epoch=state["epoch"],
        nonce=nonce,
        ciphertext=ciphertext,
        mac_tag=mac_tag,
    )

    if not ok:
        return _err("Failed to save record", 500)

    audit.append(RECORD_STORED, {
        "record_id": record_id,
        "epoch":     state["epoch"],
        "server":    SERVER_ID,
    })

    # ── SERVER B SPECIFIC: only mirror if primary ──
    if state["role"] == "primary":
        mirror_data = {
            "record_id": record_id,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "mac_tag": mac_tag.hex(),
        }
        threading.Thread(
            target=_notify_peer,
            args=["/store", mirror_data],
            daemon=True
        ).start()

    return _ok({"record_id": record_id, "epoch": state["epoch"]})



@app.route("/fetch/<record_id>", methods=["GET"])
def fetch_record(record_id: str):
    ip = _get_request_ip()
    _check_breach(ip)

    if state["isolated"]:
        return _err("Server B is isolated", 503)

    rec = store.get(record_id)
    if rec is None:
        return _err(f"Record '{record_id}' not found", 404)

    audit.append(RECORD_FETCHED, {
        "record_id": record_id,
        "epoch":     rec["epoch"],
        "server":    SERVER_ID,
    })

    return _ok({
        "record_id":  rec["id"],
        "epoch":      rec["epoch"],
        "nonce":      rec["nonce"].hex(),
        "ciphertext": rec["ciphertext"].hex(),
        "mac_tag":    rec["mac_tag"].hex(),
        "created_at": rec["created_at"],
        "updated_at": rec["updated_at"],
    })


@app.route("/fetch_payload/<record_id>", methods=["GET"])
def fetch_payload(record_id: str):
    ip = _get_request_ip()
    _check_breach(ip)

    if state["isolated"]:
        return _err("Server B is isolated", 503)
    if state["current_key"] is None:
        return _err("Server not initialised", 503)

    rec = store.get(record_id)
    if rec is None:
        return _err(f"Record '{record_id}' not found", 404)

    try:
        plaintext = decrypt(
            state["current_key"],
            rec["nonce"],
            rec["ciphertext"],
            rec["mac_tag"]
        )
    except Exception as e:
        return _err(f"Decryption failed: {e}", 500)

    audit.append(RECORD_FETCHED, {
        "record_id": record_id,
        "epoch":     rec["epoch"],
        "server":    SERVER_ID,
    })

    return _ok({
        "record_id": rec["id"],
        "epoch": rec["epoch"],
        "payload_b64": base64.b64encode(plaintext).decode('utf-8')
    })


@app.route("/fetch/all", methods=["GET"])
def fetch_all():
    ip = _get_request_ip()
    _check_breach(ip)

    if state["isolated"]:
        return _err("Server B is isolated", 503)

    all_recs = store.get_all()
    metadata = [
        {
            "id":         r["id"],
            "epoch":      r["epoch"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }
        for r in all_recs
    ]
    return _ok({"records": metadata, "total": len(metadata)})


@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    data       = request.get_json() or {}
    peer_score = float(data.get("score", 0.0))
    detector.update_peer_score(peer_score)
    return _ok({
        "score": detector.current_score,
        "epoch": state["epoch"],
        "role":  state["role"],
    })


@app.route("/score", methods=["GET"])
def score():
    ip      = _get_request_ip()
    current = detector.current_score or detector.compute(ip)
    status  = detector.get_status()
    return _ok({
        "score":   current,
        "theta":   THETA,
        "breach":  current >= THETA,
        "signals": status.get("signals", {}),
        "history": status.get("history", []),
    })


@app.route("/ratchet", methods=["POST"])
def trigger_ratchet_endpoint():
    data = request.get_json() or {}

    if state["isolated"]:
        return _err("Server B is already isolated", 409)
    if state["ratcheting"]:
        return _err("Ratchet already in progress", 409)
    if state["current_key"] is None:
        return _err("Server not initialised", 503)

    reason = data.get("reason", "manual")
    t = threading.Thread(target=_trigger_ratchet, daemon=True)
    t.start()

    return _ok({
        "message":   "Ratchet initiated",
        "old_epoch": state["epoch"],
        "reason":    reason,
    })


@app.route("/promote", methods=["POST"])
def promote():
    """
    Called by peer after it ratchets (when peer was primary).
    Tells this server to become primary and derive K_n+1 from K_n.

    Key derivation:
        Both servers start with the same K_n (from key ceremony).
        ratchet() now uses a shared salt (no server_id) so:
            ratchet(K_n, epoch=n+1) ≡ same result on both servers.
        This server independently computes K_n+1 without the key
        ever transiting the network.
    """
    data      = request.get_json() or {}
    new_epoch = int(data.get("new_epoch", state["epoch"]))
    peer_id   = data.get("from_server", "peer")

    with _lock:
        # Independently derive K_n+1 from our current K_n.
        # The ratcheting peer derived the same key because ratchet()
        # uses a shared (server-id-independent) salt.
        if state["current_key"] is not None:
            old_key_snap         = bytes(state["current_key"])
            state["current_key"] = ratchet(old_key_snap, epoch=new_epoch)

        # Clear any stale flags left over from the isolation period
        state["isolated"]   = False
        state["ratcheting"] = False
        state["role"]       = "primary"
        state["epoch"]      = new_epoch

    # Clear residual breach signals so we can ratchet again if needed
    detector.reset()

    # Pull epoch N+1 records from the isolated peer in the background
    threading.Thread(
        target=_sync_records_from_peer,
        args=[new_epoch],
        daemon=True,
    ).start()

    audit.append(FAILOVER_COMPLETE, {
        "new_primary": SERVER_ID,
        "epoch":       new_epoch,
        "reason":      f"instructed by {peer_id}",
    })

    print(f"[{SERVER_ID}] Promoted by {peer_id} — primary at epoch {new_epoch}")
    return _ok({"message": f"{SERVER_ID} promoted to primary", "role": state["role"]})


@app.route("/isolate", methods=["POST"])
def isolate():
    """
    Called by peer after it promotes itself (when peer was standby).
    Tells this server to stand down and clear breach detector state.

    IMPORTANT: detector.reset() is called here so residual breach
    signals accumulated during the standby period don’t prevent
    this server from ratcheting again when it is next promoted.
    """
    data      = request.get_json() or {}
    new_epoch = int(data.get("new_epoch", state["epoch"]))
    peer_id   = data.get("from_server", "peer")

    with _lock:
        state["isolated"]   = True
        state["ratcheting"] = False
        state["role"]       = "standby"
        state["epoch"]      = new_epoch

    # CRITICAL: reset detector so residual signals from the previous
    # breach cycle don’t permanently block ratcheting on next promotion.
    detector.reset()

    audit.append(SERVER_ISOLATED, {
        "server": SERVER_ID,
        "epoch":  new_epoch,
        "reason": f"instructed by {peer_id}",
    })

    print(f"[{SERVER_ID}] Isolated by {peer_id} — standby at epoch {new_epoch}")
    return _ok({"message": f"{SERVER_ID} isolated", "role": state["role"]})

@app.route("/audit", methods=["GET"])
def get_audit():
    if state["isolated"]:
        return _err("Server B is isolated", 503)
    last_n  = request.args.get("last", type=int)
    entries = audit.get_last(last_n) if last_n else audit.get_all()
    return _ok({"entries": entries, "total": audit.count()})


@app.route("/audit/summary", methods=["GET"])
def audit_summary():
    if state["isolated"]:
        return _err("Server B is isolated", 503)
    return _ok(audit.summary())


@app.route("/audit/verify", methods=["GET"])
def audit_verify():
    valid, message = audit.verify_chain()
    return _ok({"valid": valid, "message": message})


@app.route("/simulate_breach", methods=["POST"])
def simulate_breach():
    if state["isolated"]:
        return _err("Server is isolated", 409)
        
    data      = request.get_json() or {}
    intensity = int(data.get("intensity", 2))
    rate_v    = int(data.get("rate", 0))
    auth_v    = int(data.get("auth", 0))

    auth_count = max(auth_v // 10, intensity * 3)
    rate_count = max(rate_v // 5, intensity * 10)

    for _ in range(auth_count):
        detector.record_auth_failure("45.33.32.156")
    for _ in range(rate_count):
        detector.record_request("45.33.32.156")

    score = detector.compute("45.33.32.156")

    if score >= THETA and not state["ratcheting"] and not state["isolated"]:
        audit.append(BREACH_SCORE_HIGH, {
            "score":  score,
            "ip":     "45.33.32.156",
            "epoch":  state["epoch"],
            "server": SERVER_ID,
        })
        t = threading.Thread(target=_trigger_ratchet, daemon=True)
        t.start()

    return _ok({
        "message":   "Breach simulation injected",
        "intensity": intensity,
        "score":     score,
        "breach":    score >= THETA,
    })


@app.route("/reset", methods=["POST"])
def reset_server():
    """
    Clear Server B state in preparation for a new key ceremony.
    Server A drives the full reset: it generates the new key and will
    push it to Server B via /init. This endpoint just clears B’s state
    so it’s ready to accept the incoming /init call.
    """
    with _lock:
        state["current_key"] = None
        state["isolated"]    = False
        state["role"]        = "standby"
        state["ratcheting"]  = False
        state["epoch"]       = 0

    detector.reset()
    return _ok({"message": "Server B reset complete — awaiting new key from Server A"})


@app.route("/rejoin", methods=["POST"])
def rejoin():
    """
    Allow this isolated server to rejoin with a new key from its peer.
    Used for manual recovery when a server needs to sync without a full
    reset — peer POSTs here with the current epoch’s key.
    """
    data      = request.get_json() or {}
    key_hex   = data.get("key_hex", "")
    new_epoch = int(data.get("epoch", state["epoch"]))

    if not key_hex:
        return _err("Missing key_hex")
    try:
        new_key = bytes.fromhex(key_hex)
    except ValueError:
        return _err("Invalid key_hex")
    if len(new_key) != 32:
        return _err("Key must be 32 bytes")

    with _lock:
        state["current_key"] = new_key
        state["epoch"]       = new_epoch
        state["isolated"]    = False
        state["ratcheting"]  = False

    detector.reset()
    print(f"[{SERVER_ID}] Rejoined — epoch {new_epoch}")
    return _ok({"message": f"{SERVER_ID} rejoined", "epoch": new_epoch, "role": state["role"]})


@app.route("/internal/sync", methods=["GET"])
def internal_sync():
    """
    Peer-to-peer record synchronisation — bypasses isolation check.

    When this server is isolated it normally returns 503 on /fetch.
    However the newly-promoted peer needs to pull epoch-N+1 records
    that were re-encrypted here but never pushed (because the peer’s
    /store was returning 503). This endpoint serves those records
    without checking isolation status.

    Query param:
        epoch (int, optional) — filter by epoch; default = current
    """
    epoch = request.args.get("epoch", type=int, default=state["epoch"])

    try:
        recs = store.get_all_by_epoch(epoch)
    except Exception:
        recs = store.get_all()  # fallback if get_all_by_epoch unavailable

    result = [
        {
            "record_id":  r["id"],
            "epoch":      r["epoch"],
            "nonce":      r["nonce"].hex(),
            "ciphertext": r["ciphertext"].hex(),
            "mac_tag":    r["mac_tag"].hex(),
        }
        for r in recs
        if r["epoch"] == epoch
    ]
    return _ok({"records": result, "total": len(result), "epoch": epoch})


# ─────────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────────

def start():
    audit.append(SERVER_STARTED, {
        "server": SERVER_ID,
        "port":   SERVER_PORT,
        "role":   "standby",
    })

    print(f"[{SERVER_ID}] Starting on port {SERVER_PORT}...")
    print(f"[{SERVER_ID}] Role: standby")
    print(f"[{SERVER_ID}] Peer: {PEER_URL}")

    hb = threading.Thread(target=_heartbeat_loop, daemon=True)
    hb.start()
    print(f"[{SERVER_ID}] Heartbeat thread started")

    app.run(host="0.0.0.0", port=SERVER_PORT,
            debug=False, threaded=True)


if __name__ == "__main__":
    start()