# server_b/app.py
# HYDRA Server B — Standby server

import sys
import os
import time
import threading
from reencrypt import run_reencryption

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding='utf-8')

from flask import Flask, request, jsonify
import requests as http

from core.xchacha20 import encrypt, decrypt, generate_key, generate_nonce
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

    # Derive new key + immediately zero old key
    new_key = ratchet(old_key, epoch=new_epoch, server_id=SERVER_ID)
    zero_key(old_key)
    print(f"[{SERVER_ID}] K_{old_epoch} erased")

    # Re-encrypt all records
    result = run_reencryption(
    old_key       = old_key,
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

    # ── SERVER B SPECIFIC: promote self to primary ──
    with _lock:
        state["role"]     = "primary"
        state["isolated"] = False

    audit.append(FAILOVER_COMPLETE, {
        "new_primary": SERVER_ID,
        "epoch":       new_epoch,
    })

    print(f"[{SERVER_ID}] PROMOTED to primary — epoch {new_epoch}")

    # ── SERVER B SPECIFIC: notify Server A to isolate ──
    print(f"[{SERVER_ID}] Notifying Server A to isolate...")
    notified = _notify_peer("/isolate", {
        "new_epoch":   new_epoch,
        "from_server": SERVER_ID,
    })

    if notified:
        print(f"[{SERVER_ID}] Server A notified to isolate")
    else:
        print(f"[{SERVER_ID}] WARNING: Could not reach Server A")

    detector.reset()
    print(f"[{SERVER_ID}] Now primary. Server A is standby.")


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


@app.route("/fetch/all", methods=["GET"])
def fetch_all():
    ip = _get_request_ip()
    _check_breach(ip)

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
    current = detector.compute(ip)
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


# ── SERVER B SPECIFIC: handles /promote (called by Server A) ──
@app.route("/promote", methods=["POST"])
def promote():
    """
    Called by Server A when it detects a breach.
    Server B takes over as primary.
    """
    data      = request.get_json() or {}
    new_epoch = int(data.get("new_epoch", state["epoch"] + 1))

    with _lock:
        state["role"]     = "primary"
        state["epoch"]    = new_epoch
        state["isolated"] = False

    audit.append(FAILOVER_COMPLETE, {
        "new_primary": SERVER_ID,
        "epoch":       new_epoch,
        "from":        data.get("from_server", "server_a"),
    })

    print(f"[{SERVER_ID}] PROMOTED to primary — epoch {new_epoch}")
    return _ok({
        "message":   "Server B promoted to primary",
        "new_epoch": new_epoch,
        "role":      state["role"],
    })


# ── SERVER B SPECIFIC: does NOT handle /isolate ──
# Server B never gets told to isolate by Server A


@app.route("/audit", methods=["GET"])
def get_audit():
    last_n  = request.args.get("last", type=int)
    entries = audit.get_last(last_n) if last_n else audit.get_all()
    return _ok({"entries": entries, "total": audit.count()})


@app.route("/audit/summary", methods=["GET"])
def audit_summary():
    return _ok(audit.summary())


@app.route("/audit/verify", methods=["GET"])
def audit_verify():
    valid, message = audit.verify_chain()
    return _ok({"valid": valid, "message": message})


@app.route("/simulate_breach", methods=["POST"])
def simulate_breach():
    data      = request.get_json() or {}
    intensity = int(data.get("intensity", 2))

    for _ in range(intensity * 3):
        detector.record_auth_failure("45.33.32.156")
    for _ in range(intensity * 10):
        detector.record_request("45.33.32.156")

    score = detector.compute("45.33.32.156")
    return _ok({
        "message":   "Breach simulation injected",
        "intensity": intensity,
        "score":     score,
        "breach":    score >= THETA,
    })


@app.route("/reset", methods=["POST"])
def reset_server():
    with _lock:
        state["isolated"]   = False
        state["role"]       = "standby"    # B resets to standby
        state["ratcheting"] = False

    detector.reset()
    return _ok({"message": "Server B reset complete"})


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