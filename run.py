# run.py
# HYDRA system entry point
# Starts both servers, runs key ceremony, loads data,
# starts heartbeat monitor, keeps system alive.
#
# Usage:
#   python run.py
#   python run.py --no-data     (skip loading Synthea records)
#   python run.py --reset       (wipe databases and start fresh)

import sys
import os
import time
import json
import subprocess
import argparse
import threading
import signal

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding='utf-8')

try:
    import requests
except ImportError:
    print("ERROR: requests not installed.")
    print("Run: pip install flask requests")
    sys.exit(1)

from core.xchacha20 import encrypt, generate_key, generate_nonce
from core.shamir    import split_key, encode_share_for_server
from heartbeat      import HeartbeatMonitor, start_background


# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

SERVER_A_URL  = "http://127.0.0.1:5001"
SERVER_B_URL  = "http://127.0.0.1:5002"

SERVER_A_SCRIPT = os.path.join(ROOT, "server_a", "app.py")
SERVER_B_SCRIPT = os.path.join(ROOT, "server_b", "app.py")

DATA_PATH     = os.path.join(ROOT, "data", "processed", "records.json")
TOKEN_PATH    = os.path.join(ROOT, "client", "token.json")

STARTUP_TIMEOUT  = 15    # seconds to wait for servers to come up
STARTUP_POLL     = 0.5   # seconds between /status polls
STORE_BATCH_SIZE = 10    # records to store per batch


# ─────────────────────────────────────────────
# TERMINAL HELPERS
# ─────────────────────────────────────────────

# ANSI colours
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):    print(f"  {GREEN}[OK]{RESET}    {msg}")
def err(msg):   print(f"  {RED}[ERR]{RESET}   {msg}")
def info(msg):  print(f"  {BLUE}[INFO]{RESET}  {msg}")
def warn(msg):  print(f"  {YELLOW}[WARN]{RESET}  {msg}")
def step(n, msg): print(f"\n{BOLD}Step {n} — {msg}{RESET}")
def divider():  print("─" * 60)


# ─────────────────────────────────────────────
# HTTP HELPERS
# ─────────────────────────────────────────────

def _post(url: str, payload: dict, timeout: int = 10) -> dict:
    """
    POST JSON to a URL.
    Returns parsed response dict.
    Raises RuntimeError on failure.
    """
    resp = requests.post(url, json=payload, timeout=timeout)
    if resp.status_code != 200:
        raise RuntimeError(
            f"POST {url} -> {resp.status_code}: {resp.text[:200]}"
        )
    return resp.json()


def _get(url: str, timeout: int = 5) -> dict:
    """
    GET a URL.
    Returns parsed response dict.
    Raises on failure.
    """
    resp = requests.get(url, timeout=timeout)
    if resp.status_code != 200:
        raise RuntimeError(
            f"GET {url} -> {resp.status_code}: {resp.text[:200]}"
        )
    return resp.json()


# ─────────────────────────────────────────────
# STEP 1 + 2: START SERVERS
# ─────────────────────────────────────────────

def start_server(script_path: str, label: str) -> subprocess.Popen:
    """
    Start a Flask server as a subprocess.

    Uses the same Python interpreter that is running run.py
    so virtual environments work correctly.

    Args:
        script_path: absolute path to the app.py script
        label:       human-readable label for logging

    Returns:
        subprocess.Popen handle — kept alive for the duration
        of the session, terminated on shutdown.
    """
    info(f"Starting {label} ({script_path})...")

    proc = subprocess.Popen(
        [sys.executable, script_path],
        stdout = sys.stdout,
        stderr = sys.stdout,
        cwd    = ROOT,
    )

    info(f"{label} process started (PID {proc.pid})")
    return proc


def wait_for_server(url: str, label: str,
                    timeout: float = STARTUP_TIMEOUT) -> bool:
    """
    Poll a server's /status endpoint until it responds 200
    or the timeout is reached.

    Args:
        url:     base URL of the server
        label:   human-readable label for logging
        timeout: max seconds to wait

    Returns:
        True if server came up, False if timed out
    """
    deadline = time.time() + timeout
    attempts = 0

    while time.time() < deadline:
        try:
            resp = requests.get(f"{url}/status", timeout=2)
            if resp.status_code == 200:
                data = resp.json()
                ok(f"{label} is up — "
                   f"role={data.get('role')} "
                   f"epoch={data.get('epoch')}")
                return True
        except Exception:
            pass

        attempts += 1
        time.sleep(STARTUP_POLL)

    err(f"{label} did not respond after {timeout}s ({attempts} attempts)")
    return False


# ─────────────────────────────────────────────
# STEP 3: KEY CEREMONY
# ─────────────────────────────────────────────

def run_key_ceremony(epoch: int = 1) -> bytes:
    """
    Generate master key, split into shares, distribute to servers.

    Steps:
        1. Generate 32-byte master key using os.urandom
        2. Split into 3 Shamir shares (3,2) threshold
        3. POST /init to Server A with key + S1
        4. POST /init to Server B with key + S2
        5. Save S3 to client/token.json (plaintext for demo)
           In production this would be encrypted with a passphrase

    Args:
        epoch: starting key epoch (default 1)

    Returns:
        master_key bytes — kept in memory for data loading step
        (never written to disk)
    """
    info("Generating master key...")
    master_key = generate_key()
    info(f"Master key: {master_key.hex()[:16]}...{master_key.hex()[-8:]}")

    info("Splitting into (3,2) Shamir shares...")
    shares = split_key(master_key, n=3, k=2)
    # shares[0] = S1 -> Server A
    # shares[1] = S2 -> Server B
    # shares[2] = S3 -> Client token

    info(f"Share S1 (Server A): x={shares[0][0]}")
    info(f"Share S2 (Server B): x={shares[1][0]}")
    info(f"Share S3 (Token):    x={shares[2][0]}")

    # Send S1 to Server A
    info("Sending S1 to Server A...")
    s1 = encode_share_for_server(shares[0])
    try:
        resp = _post(f"{SERVER_A_URL}/init", {
            "key_hex": master_key.hex(),
            "share_x": s1["x"],
            "share_y": s1["y"],
            "epoch":   epoch,
        })
        ok(f"Server A initialised — epoch={resp.get('epoch')}")
    except Exception as e:
        raise RuntimeError(f"Failed to initialise Server A: {e}")

    # Send S2 to Server B
    info("Sending S2 to Server B...")
    s2 = encode_share_for_server(shares[1])
    try:
        resp = _post(f"{SERVER_B_URL}/init", {
            "key_hex": master_key.hex(),
            "share_x": s2["x"],
            "share_y": s2["y"],
            "epoch":   epoch,
        })
        ok(f"Server B initialised — epoch={resp.get('epoch')}")
    except Exception as e:
        raise RuntimeError(f"Failed to initialise Server B: {e}")

    # Save S3 to client token file
    info("Saving S3 to client token...")
    os.makedirs(os.path.dirname(TOKEN_PATH), exist_ok=True)

    s3 = encode_share_for_server(shares[2])
    token_data = {
        "share_x":   s3["x"],
        "share_y":   s3["y"],
        "epoch":     epoch,
        "created_at": time.time(),
        "note": (
            "S3 — client hardware token share. "
            "In production this file would be encrypted "
            "with a user passphrase using XChaCha20."
        )
    }

    with open(TOKEN_PATH, "w", encoding="utf-8") as f:
        json.dump(token_data, f, indent=2)

    ok(f"S3 saved to {TOKEN_PATH}")
    ok("Key ceremony complete")

    return master_key


# ─────────────────────────────────────────────
# STEP 4: LOAD SYNTHEA DATA
# ─────────────────────────────────────────────

def load_records(master_key: bytes) -> int:
    """
    Encrypt and store all patient records from Synthea data.

    Reads data/processed/records.json, encrypts each record
    using XChaCha20 with the master key, and POSTs to Server A.
    Server A automatically mirrors each record to Server B.

    Each record in records.json has format:
    {
        "record_id":     "patient-0001",
        "plaintext_json": "{name, dob, conditions, ...}",
        "patient_name":  "Alice Johnson",
        "patient_age":   45
    }

    Args:
        master_key: 32-byte master encryption key

    Returns:
        Number of records successfully stored
    """
    if not os.path.exists(DATA_PATH):
        warn(f"No data file found at {DATA_PATH}")
        warn("Run: python data/preprocess.py  to generate it")
        warn("Or run with --no-data to skip this step")
        return 0

    info(f"Loading records from {DATA_PATH}...")

    with open(DATA_PATH, "r", encoding="utf-8") as f:
        records = json.load(f)

    total   = len(records)
    success = 0
    failed  = 0

    info(f"Found {total} patient records to encrypt and store...")

    for i, rec in enumerate(records):
        record_id    = rec["record_id"]
        plaintext    = rec["plaintext_json"].encode("utf-8")

        try:
            # Encrypt with XChaCha20
            nonce, ciphertext, mac_tag = encrypt(master_key, plaintext)

            # POST to Server A (mirrors to B automatically)
            _post(f"{SERVER_A_URL}/store", {
                "record_id":  record_id,
                "nonce":      nonce.hex(),
                "ciphertext": ciphertext.hex(),
                "mac_tag":    mac_tag.hex(),
            }, timeout=10)

            success += 1

            # Progress every 10 records
            if (i + 1) % STORE_BATCH_SIZE == 0 or (i + 1) == total:
                pct = int(((i + 1) / total) * 100)
                print(
                    f"\r  {BLUE}[INFO]{RESET}  "
                    f"Storing records... {i+1}/{total} ({pct}%)",
                    end="", flush=True
                )

        except Exception as e:
            failed += 1
            # Don't stop — continue with remaining records
            if failed <= 3:
                print()  # newline after progress bar
                warn(f"Failed to store {record_id}: {e}")

    print()  # newline after progress bar

    if success > 0:
        ok(f"Stored {success}/{total} records "
           f"(epoch 1, XChaCha20 encrypted)")
    if failed > 0:
        warn(f"{failed} records failed to store")

    return success


# ─────────────────────────────────────────────
# STEP 5: VERIFY SYSTEM STATE
# ─────────────────────────────────────────────

def verify_system() -> bool:
    """
    Check that both servers are healthy and in sync
    after startup and data loading.

    Returns True if system is ready for demo.
    """
    try:
        status_a = _get(f"{SERVER_A_URL}/status")
        status_b = _get(f"{SERVER_B_URL}/status")

        epoch_a   = status_a.get("epoch", 0)
        epoch_b   = status_b.get("epoch", 0)
        count_a   = status_a.get("record_count", 0)
        count_b   = status_b.get("record_count", 0)
        role_a    = status_a.get("role", "unknown")
        role_b    = status_b.get("role", "unknown")
        score_a   = status_a.get("score", 0.0)
        score_b   = status_b.get("score", 0.0)

        info(f"Server A: role={role_a:<8} "
             f"epoch={epoch_a} records={count_a} "
             f"score={score_a:.3f}")
        info(f"Server B: role={role_b:<8} "
             f"epoch={epoch_b} records={count_b} "
             f"score={score_b:.3f}")

        # Check sync
        if epoch_a != epoch_b:
            warn(f"Epoch mismatch: A={epoch_a} B={epoch_b}")
            return False

        if count_a != count_b:
            warn(f"Record count mismatch: A={count_a} B={count_b}")
            warn("Server B may still be receiving mirrored records")
            warn("This is normal — mirroring happens asynchronously")

        if role_a == "primary" and role_b == "standby":
            ok("Roles correct: A=primary B=standby")
        else:
            warn(f"Unexpected roles: A={role_a} B={role_b}")

        return True

    except Exception as e:
        err(f"System verification failed: {e}")
        return False


# ─────────────────────────────────────────────
# CLEANUP
# ─────────────────────────────────────────────

def _cleanup_databases():
    """
    Remove server databases for a clean reset.
    Only called with --reset flag.
    """
    db_files = [
        os.path.join(ROOT, "server_a", "server_a.db"),
        os.path.join(ROOT, "server_b", "server_b.db"),
        os.path.join(ROOT, "server_a", "audit_a.json"),
        os.path.join(ROOT, "server_b", "audit_b.json"),
        os.path.join(ROOT, "reencrypt_audit.json"),
        os.path.join(ROOT, "heartbeat_log.json"),
        TOKEN_PATH,
    ]

    for path in db_files:
        if os.path.exists(path):
            os.remove(path)
            info(f"Removed: {path}")

    ok("Clean reset complete")


def _shutdown(procs: list, monitor: HeartbeatMonitor):
    """
    Graceful shutdown — terminate server subprocesses.
    Called on Ctrl+C or SIGTERM.
    """
    print(f"\n{YELLOW}Shutting down HYDRA...{RESET}")

    if monitor:
        monitor.running = False

    for label, proc in procs:
        if proc and proc.poll() is None:
            info(f"Terminating {label} (PID {proc.pid})...")
            proc.terminate()
            try:
                proc.wait(timeout=3)
                ok(f"{label} stopped")
            except subprocess.TimeoutExpired:
                proc.kill()
                warn(f"{label} force-killed")

    print(f"{GREEN}HYDRA shutdown complete.{RESET}\n")


# ─────────────────────────────────────────────
# STATUS PRINTER (periodic)
# ─────────────────────────────────────────────

def _status_loop(interval: int = 30):
    """
    Background thread that prints a status summary
    every `interval` seconds so the operator knows
    the system is alive.
    """
    while True:
        time.sleep(interval)
        try:
            sa = _get(f"{SERVER_A_URL}/status", timeout=3)
            sb = _get(f"{SERVER_B_URL}/status", timeout=3)
            ts = time.strftime("%H:%M:%S")
            print(
                f"\n[{ts}] "
                f"A: {sa.get('role','?'):<8} "
                f"epoch={sa.get('epoch',0)} "
                f"score={sa.get('score',0):.3f}  |  "
                f"B: {sb.get('role','?'):<8} "
                f"epoch={sb.get('epoch',0)} "
                f"score={sb.get('score',0):.3f}"
            )
        except Exception:
            pass


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="HYDRA — start the full dual-server system"
    )
    parser.add_argument(
        "--no-data",
        action="store_true",
        help="Skip loading Synthea patient records"
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Wipe databases and start completely fresh"
    )
    parser.add_argument(
        "--epoch",
        type=int,
        default=1,
        help="Starting key epoch (default: 1)"
    )
    args = parser.parse_args()

    # ── Banner ─────────────────────────────────
    print()
    divider()
    print(f"{BOLD}  HYDRA — Hybrid Dual-Server Reactive Encryption{RESET}")
    print(f"  Hybrid Dual-Server Reactive Encryption Architecture")
    divider()
    print()

    # ── Reset if requested ─────────────────────
    if args.reset:
        step("0", "Clean reset")
        _cleanup_databases()

    procs   = []
    monitor = None

    # ── Register signal handler ─────────────────
    def _signal_handler(sig, frame):
        _shutdown(procs, monitor)
        sys.exit(0)

    signal.signal(signal.SIGINT,  _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    try:
        # ── Step 1: Start Server A ──────────────
        step("1", "Starting Server A (primary, port 5001)")
        proc_a = start_server(SERVER_A_SCRIPT, "Server A")
        procs.append(("Server A", proc_a))

        # Small delay so Server A binds its port first
        time.sleep(1.0)

        # ── Step 2: Start Server B ──────────────
        step("2", "Starting Server B (standby, port 5002)")
        proc_b = start_server(SERVER_B_SCRIPT, "Server B")
        procs.append(("Server B", proc_b))

        # ── Step 3: Wait for both servers ───────
        step("3", "Waiting for servers to be ready")
        a_ready = wait_for_server(SERVER_A_URL, "Server A")
        b_ready = wait_for_server(SERVER_B_URL, "Server B")

        if not a_ready or not b_ready:
            err("One or both servers failed to start")
            err("Check that ports 5001 and 5002 are free")
            _shutdown(procs, monitor)
            sys.exit(1)

        # ── Step 4: Key ceremony ─────────────────
        step("4", "Running key ceremony")
        try:
            master_key = run_key_ceremony(epoch=args.epoch)
        except RuntimeError as e:
            err(f"Key ceremony failed: {e}")
            _shutdown(procs, monitor)
            sys.exit(1)

        # ── Step 5: Load Synthea data ────────────
        if not args.no_data:
            step("5", "Loading and encrypting patient records")
            count = load_records(master_key)
            if count == 0:
                warn("No records loaded — system is running but empty")
                warn("Generate data with: python data/preprocess.py")
        else:
            step("5", "Skipping data load (--no-data)")
            info("System running with no patient records")

        # Zero master key from memory after use
        # (it now lives only in the servers)
        master_key = bytearray(master_key)
        for i in range(len(master_key)):
            master_key[i] = 0
        del master_key
        info("Master key zeroed from run.py memory")

        # ── Step 6: Start heartbeat monitor ─────
        step("6", "Starting heartbeat monitor")
        monitor = HeartbeatMonitor()
        start_background(monitor)

        # ── Step 7: Verify system ────────────────
        step("7", "Verifying system state")
        time.sleep(2)   # wait for mirroring to settle
        verify_system()

        # ── Step 8: Start status printer ────────
        status_thread = threading.Thread(
            target=_status_loop,
            args=[30],
            daemon=True
        )
        status_thread.start()

        # ── Ready ────────────────────────────────
        print()
        divider()
        print(f"{GREEN}{BOLD}  HYDRA is running{RESET}")
        divider()
        print(f"\n  Server A (primary):  {SERVER_A_URL}")
        print(f"  Server B (standby):  {SERVER_B_URL}")
        print(f"\n  Endpoints:")
        print(f"    {SERVER_A_URL}/status")
        print(f"    {SERVER_A_URL}/score")
        print(f"    {SERVER_A_URL}/audit")
        print(f"    {SERVER_A_URL}/fetch/all")
        print(f"\n  Demo:")
        print(f"    Simulate breach:  "
              f"POST {SERVER_A_URL}/simulate_breach")
        print(f"    Manual ratchet:   "
              f"POST {SERVER_A_URL}/ratchet")
        print(f"    Reset system:     "
              f"POST {SERVER_A_URL}/reset + "
              f"POST {SERVER_B_URL}/reset")
        print(f"\n  Token: {TOKEN_PATH}")
        print(f"\n  Press Ctrl+C to stop all servers.\n")
        divider()

        # ── Keep alive ───────────────────────────
        while True:
            # Check if servers are still running
            if proc_a.poll() is not None:
                warn(f"Server A exited unexpectedly "
                     f"(code {proc_a.returncode})")

            if proc_b.poll() is not None:
                warn(f"Server B exited unexpectedly "
                     f"(code {proc_b.returncode})")

            time.sleep(5)

    except KeyboardInterrupt:
        pass

    finally:
        _shutdown(procs, monitor)


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    main()