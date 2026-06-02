# heartbeat.py
# Standalone heartbeat monitor for HYDRA
# Runs as a separate process watching both servers
# and logging their health continuously.
#
# Can be:
#   1. Run standalone: python heartbeat.py
#   2. Imported by run.py which starts everything together

import sys
import os
import time
import json
import threading

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding='utf-8')

try:
    import requests
except ImportError:
    print("ERROR: requests not installed. Run: pip install requests")
    sys.exit(1)


# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

SERVER_A_URL      = "http://127.0.0.1:5001"
SERVER_B_URL      = "http://127.0.0.1:5002"
HEARTBEAT_INTERVAL = 5     # seconds between beats
REQUEST_TIMEOUT    = 3     # seconds before giving up on a request
LOG_PATH           = os.path.join(ROOT, "heartbeat_log.json")

# ANSI colours for terminal output
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


# ─────────────────────────────────────────────
# SERVER SNAPSHOT
# ─────────────────────────────────────────────

class ServerSnapshot:
    """
    Holds the most recent known state of one server.

    Updated every heartbeat cycle.
    Used to detect changes between cycles.
    """

    def __init__(self, server_id: str, url: str):
        self.server_id    = server_id
        self.url          = url

        # Latest values from /status
        self.alive        = False
        self.role         = "unknown"
        self.epoch        = 0
        self.score        = 0.0
        self.is_breach    = False
        self.isolated     = False
        self.ratcheting   = False
        self.record_count = 0
        self.initialised  = False

        # Tracking
        self.last_seen    = None     # timestamp of last successful contact
        self.consecutive_failures = 0
        self.total_beats  = 0
        self.failed_beats = 0

    def update_from_status(self, data: dict):
        """Update snapshot from a /status response dict."""
        self.alive        = True
        self.role         = data.get("role",         "unknown")
        self.epoch        = data.get("epoch",        0)
        self.score        = data.get("score",        0.0)
        self.is_breach    = data.get("is_breach",    False)
        self.isolated     = data.get("isolated",     False)
        self.ratcheting   = data.get("ratcheting",   False)
        self.record_count = data.get("record_count", 0)
        self.initialised  = data.get("initialised",  False)
        self.last_seen    = time.time()
        self.consecutive_failures = 0

    def mark_failed(self):
        """Mark this beat as failed — server unreachable."""
        self.alive = False
        self.consecutive_failures += 1
        self.failed_beats += 1


# ─────────────────────────────────────────────
# HEARTBEAT MONITOR
# ─────────────────────────────────────────────

class HeartbeatMonitor:
    """
    Monitors both HYDRA servers continuously.

    Every HEARTBEAT_INTERVAL seconds:
        1. Polls /status on both servers
        2. Sends each server the other's breach score
           via POST /heartbeat
        3. Logs health to file
        4. Prints live status to terminal
        5. Detects anomalies:
           - Server went offline
           - Server changed role unexpectedly
           - Breach score crossed theta
           - Epoch mismatch between servers
           - Both servers claiming to be primary
    """

    def __init__(self):
        self.server_a  = ServerSnapshot("server_a", SERVER_A_URL)
        self.server_b  = ServerSnapshot("server_b", SERVER_B_URL)
        self.running   = False
        self.beat_count = 0

        # History for the dashboard
        self.history   = []    # list of beat summaries
        self._lock     = threading.Lock()


    # ── HTTP helpers ───────────────────────────

    def _get_status(self, snap: ServerSnapshot) -> bool:
        """
        Poll /status on a server and update its snapshot.

        Returns True on success, False if server unreachable.
        """
        snap.total_beats += 1
        try:
            resp = requests.get(
                f"{snap.url}/status",
                timeout=REQUEST_TIMEOUT
            )
            if resp.status_code == 200:
                snap.update_from_status(resp.json())
                return True
            else:
                snap.mark_failed()
                return False
        except Exception:
            snap.mark_failed()
            return False


    def _send_heartbeat(self, to_snap: ServerSnapshot,
                        from_snap: ServerSnapshot) -> bool:
        """
        Send from_snap's score to to_snap via POST /heartbeat.

        This is how servers update their gossip score —
        the heartbeat monitor acts as the relay.

        Returns True on success.
        """
        try:
            resp = requests.post(
                f"{to_snap.url}/heartbeat",
                json={
                    "from":  from_snap.server_id,
                    "score": from_snap.score,
                    "epoch": from_snap.epoch,
                    "role":  from_snap.role,
                },
                timeout=REQUEST_TIMEOUT
            )
            return resp.status_code == 200
        except Exception:
            return False


    # ── Anomaly detection ──────────────────────

    def _check_anomalies(self) -> list:
        """
        Check for system-level anomalies after each beat.

        Returns list of anomaly strings to log/display.
        Each string describes one detected problem.
        """
        anomalies = []
        a = self.server_a
        b = self.server_b

        # Both servers down
        if not a.alive and not b.alive:
            anomalies.append("CRITICAL: Both servers are unreachable")

        # Single server down
        if not a.alive and b.alive:
            anomalies.append("WARNING: Server A is unreachable")
        if not b.alive and a.alive:
            anomalies.append("WARNING: Server B is unreachable")

        # Both claiming primary — split brain
        if (a.alive and b.alive and
                a.role == "primary" and b.role == "primary"):
            anomalies.append(
                "CRITICAL: Split brain — both servers claim PRIMARY role"
            )

        # Neither is primary
        if (a.alive and b.alive and
                a.role != "primary" and b.role != "primary"):
            anomalies.append(
                "WARNING: No primary server — both are standby"
            )

        # Epoch mismatch
        if a.alive and b.alive and a.epoch != b.epoch:
            anomalies.append(
                f"WARNING: Epoch mismatch — "
                f"A={a.epoch} B={b.epoch}"
            )

        # Record count mismatch
        if (a.alive and b.alive and
                a.initialised and b.initialised and
                a.record_count != b.record_count):
            anomalies.append(
                f"WARNING: Record count mismatch — "
                f"A={a.record_count} B={b.record_count}"
            )

        # Breach score high but no ratchet yet
        if a.alive and a.score >= 0.55 and not a.ratcheting:
            anomalies.append(
                f"BREACH: Server A score critical: {a.score:.3f}"
            )
        if b.alive and b.score >= 0.55 and not b.ratcheting:
            anomalies.append(
                f"BREACH: Server B score critical: {b.score:.3f}"
            )

        # Ratchet in progress
        if a.alive and a.ratcheting:
            anomalies.append(
                f"INFO: Server A ratchet in progress — epoch {a.epoch}"
            )
        if b.alive and b.ratcheting:
            anomalies.append(
                f"INFO: Server B ratchet in progress — epoch {b.epoch}"
            )

        return anomalies


    # ── Display ────────────────────────────────

    def _score_bar(self, score: float, width: int = 20) -> str:
        """
        Render a score as a visual bar.

        0.0 ──────────────────── 1.0
        [████████░░░░░░░░░░░░] 0.42
        """
        filled = int(score * width)
        empty  = width - filled

        if score >= 0.55:
            color = RED
        elif score >= 0.35:
            color = YELLOW
        else:
            color = GREEN

        bar = color + "#" * filled + RESET + "." * empty
        return f"[{bar}] {score:.3f}"


    def _print_status(self, anomalies: list):
        """
        Print a live status line to the terminal.
        Overwrites the previous output for a clean display.
        """
        a = self.server_a
        b = self.server_b

        now = time.strftime("%H:%M:%S")

        print(f"\n{BOLD}── HYDRA Heartbeat Monitor  "
              f"{now}  beat #{self.beat_count} ──{RESET}")

        # Server A
        if a.alive:
            role_color = GREEN if a.role == "primary" else BLUE
            print(
                f"  Server A  "
                f"{role_color}{a.role.upper():<8}{RESET}  "
                f"epoch={a.epoch:<3}  "
                f"records={a.record_count:<5}  "
                f"score={self._score_bar(a.score)}"
            )
        else:
            print(f"  Server A  {RED}OFFLINE{RESET}  "
                  f"(failures: {a.consecutive_failures})")

        # Server B
        if b.alive:
            role_color = GREEN if b.role == "primary" else BLUE
            print(
                f"  Server B  "
                f"{role_color}{b.role.upper():<8}{RESET}  "
                f"epoch={b.epoch:<3}  "
                f"records={b.record_count:<5}  "
                f"score={self._score_bar(b.score)}"
            )
        else:
            print(f"  Server B  {RED}OFFLINE{RESET}  "
                  f"(failures: {b.consecutive_failures})")

        # Anomalies
        if anomalies:
            print()
            for anomaly in anomalies:
                if "CRITICAL" in anomaly:
                    print(f"  {RED}{BOLD}{anomaly}{RESET}")
                elif "BREACH" in anomaly:
                    print(f"  {RED}{anomaly}{RESET}")
                elif "WARNING" in anomaly:
                    print(f"  {YELLOW}{anomaly}{RESET}")
                else:
                    print(f"  {BLUE}{anomaly}{RESET}")


    # ── Logging ────────────────────────────────

    def _log_beat(self, anomalies: list):
        """
        Append this beat's summary to the log file.
        Keeps the last 1000 beats in memory.
        """
        beat = {
            "beat":      self.beat_count,
            "timestamp": time.time(),
            "server_a": {
                "alive":        self.server_a.alive,
                "role":         self.server_a.role,
                "epoch":        self.server_a.epoch,
                "score":        self.server_a.score,
                "record_count": self.server_a.record_count,
            },
            "server_b": {
                "alive":        self.server_b.alive,
                "role":         self.server_b.role,
                "epoch":        self.server_b.epoch,
                "score":        self.server_b.score,
                "record_count": self.server_b.record_count,
            },
            "anomalies": anomalies,
        }

        with self._lock:
            self.history.append(beat)
            if len(self.history) > 1000:
                self.history.pop(0)

        # Write to file (last 100 beats only to keep file small)
        try:
            with open(LOG_PATH, "w", encoding="utf-8") as f:
                json.dump(self.history[-100:], f, indent=2)
        except Exception:
            pass


    # ── Main beat cycle ────────────────────────

    def _beat(self):
        """
        One full heartbeat cycle.

        1. Poll both servers for status
        2. Cross-send breach scores
        3. Check for anomalies
        4. Log and display
        """
        self.beat_count += 1

        # Poll status from both servers
        self._get_status(self.server_a)
        self._get_status(self.server_b)

        # Cross-send scores (only if both alive)
        if self.server_a.alive and self.server_b.alive:
            self._send_heartbeat(self.server_b, self.server_a)
            self._send_heartbeat(self.server_a, self.server_b)

        # Check anomalies
        anomalies = self._check_anomalies()

        # Display + log
        self._print_status(anomalies)
        self._log_beat(anomalies)


    # ── Public API ─────────────────────────────

    def run_forever(self):
        """
        Start the heartbeat monitor loop.
        Runs until KeyboardInterrupt (Ctrl+C).
        """
        self.running = True
        print(f"{BOLD}HYDRA Heartbeat Monitor starting...{RESET}")
        print(f"  Server A: {SERVER_A_URL}")
        print(f"  Server B: {SERVER_B_URL}")
        print(f"  Interval: {HEARTBEAT_INTERVAL}s")
        print(f"  Log:      {LOG_PATH}")
        print(f"\nPress Ctrl+C to stop.\n")

        try:
            while self.running:
                self._beat()
                time.sleep(HEARTBEAT_INTERVAL)
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Heartbeat monitor stopped.{RESET}")
            self.running = False


    def run_once(self) -> dict:
        """
        Run exactly one beat and return the result.
        Used by run.py and the dashboard to get a snapshot.
        """
        self._beat()
        with self._lock:
            return self.history[-1] if self.history else {}


    def get_history(self, last_n: int = 20) -> list:
        """Return last N beats for the dashboard."""
        with self._lock:
            return self.history[-last_n:]


    def get_latest(self) -> dict:
        """Return the most recent beat summary."""
        with self._lock:
            return self.history[-1] if self.history else {}


    def is_healthy(self) -> bool:
        """
        Returns True if both servers are alive,
        in sync, and no breach detected.
        """
        a = self.server_a
        b = self.server_b
        return (
            a.alive and b.alive and
            a.epoch == b.epoch and
            a.score < 0.55 and
            b.score < 0.55 and
            not (a.role == "primary" and b.role == "primary")
        )


# ─────────────────────────────────────────────
# BACKGROUND THREAD HELPER
# ─────────────────────────────────────────────

def start_background(monitor: HeartbeatMonitor = None) -> HeartbeatMonitor:
    """
    Start the heartbeat monitor in a background thread.

    Used by run.py so the monitor runs alongside the servers
    without blocking the main thread.

    Args:
        monitor: existing HeartbeatMonitor instance,
                 or None to create a new one

    Returns:
        The HeartbeatMonitor instance (running in background)
    """
    if monitor is None:
        monitor = HeartbeatMonitor()

    def _loop():
        try:
            while monitor.running:
                monitor._beat()
                time.sleep(HEARTBEAT_INTERVAL)
        except Exception as e:
            print(f"[heartbeat] Background thread error: {e}")

    monitor.running = True
    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    print(f"[heartbeat] Background monitor started "
          f"(interval={HEARTBEAT_INTERVAL}s)")

    return monitor


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    monitor = HeartbeatMonitor()
    monitor.run_forever()