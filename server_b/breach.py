# server_b/breach.py
# Breach anomaly detection engine for Server B
# Pure Python — stdlib only: time, collections, math, sys

import sys
import time
import math
import collections
sys.stdout.reconfigure(encoding='utf-8')


# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

THETA             = 0.55   # breach score threshold
WINDOW_SECONDS    = 60     # sliding window for rate scoring
RATE_CEILING      = 100    # requests/min above which score = 1.0
MAX_AUTH_FAILS    = 20     # failures above which score = 1.0
HEARTBEAT_TIMEOUT = 15     # seconds before missing heartbeat is suspicious

# Trusted IP prefixes for Server A
# In production these would be your hospital's IP ranges
# Format: string prefix that trusted IPs start with
TRUSTED_IP_PREFIXES = [
    "127.",        # localhost (for development)
    "192.168.",    # local network
    "10.",         # private network
]

# Weights — must sum to 1.0
WEIGHT_RATE      = 0.25
WEIGHT_GEO       = 0.30
WEIGHT_TIMING    = 0.20
WEIGHT_AUTH      = 0.15
WEIGHT_GOSSIP    = 0.10


# ─────────────────────────────────────────────
# BREACH DETECTOR
# ─────────────────────────────────────────────

class BreachDetector:
    """
    Autonomous anomaly scorer for HYDRA Server A.

    Tracks incoming requests and computes a breach score
    between 0.0 (clean) and 1.0 (definite breach).

    When score >= THETA, the server must fire the ratchet.

    Usage:
        detector = BreachDetector()
        detector.record_request(ip="192.168.1.5")
        score = detector.compute(ip="192.168.1.5",
                                 peer_score=0.1)
        if score >= THETA:
            fire_ratchet()
    """

    def __init__(self):
        # ── Rate tracking ──────────────────────
        # deque of timestamps of recent requests
        # maxlen keeps memory bounded
        self.request_times = collections.deque(maxlen=1000)

        # ── Timing baseline ────────────────────
        # We need a baseline of normal inter-request gaps
        # to compare against. Starts empty, fills over time.
        self.baseline_gaps    = collections.deque(maxlen=50)
        self.baseline_mean    = None
        self.baseline_std     = None
        self._baseline_ready  = False

        # ── Auth failure tracking ──────────────
        # (timestamp, ip) of each failed auth attempt
        self.auth_failures = collections.deque(maxlen=100)

        # ── Gossip ────────────────────────────
        # Most recent score received from peer server
        self.peer_score           = 0.0
        self.last_heartbeat_time  = time.time()

        # ── Score history ──────────────────────
        # Last 20 computed scores for smoothing + dashboard
        self.score_history = collections.deque(maxlen=20)

        # ── Current local score ────────────────
        self.current_score = 0.0


    # ── Signal 1: Request Rate ─────────────────

    def _rate_score(self) -> float:
        """
        Compute score based on requests per minute.

        Removes timestamps older than WINDOW_SECONDS,
        then scores based on how many remain.

        Score = min(1.0, count / RATE_CEILING)

        Normal usage: < 20 req/min → score near 0.0
        Attacker:     100+ req/min → score 1.0
        """
        now = time.time()
        cutoff = now - WINDOW_SECONDS

        # Remove requests outside the window
        while self.request_times and self.request_times[0] < cutoff:
            self.request_times.popleft()

        count = len(self.request_times)
        return min(1.0, count / RATE_CEILING)


    # ── Signal 2: Geographic Deviation ─────────

    def _geo_score(self, ip: str) -> float:
        """
        Score based on whether the IP is in a trusted range.

        Checks if the IP starts with any trusted prefix.
        If not trusted → score 1.0 immediately.

        In a real deployment you would use a GeoIP database.
        For HYDRA we use IP prefix matching — clean and
        requires no external library.

        Returns:
            0.0 if IP is trusted
            1.0 if IP is from an unknown/untrusted range
        """
        if not ip:
            return 0.5   # unknown IP — moderately suspicious

        for prefix in TRUSTED_IP_PREFIXES:
            if ip.startswith(prefix):
                return 0.0   # trusted

        return 1.0   # untrusted


    # ── Signal 3: Timing Drift ──────────────────

    def _timing_score(self) -> float:
        """
        Score based on inter-request timing patterns.

        Legitimate users have irregular timing (human behaviour).
        Automated attackers are either:
            - Too regular (scripted, low std dev)
            - Too random (probing, very high std dev)

        Both deviate from the established baseline.

        Steps:
            1. Compute gaps between recent request timestamps
            2. Compute mean and std dev of those gaps
            3. Compare to baseline std dev
            4. Large deviation = suspicious

        Returns 0.0 if not enough data to compute baseline.
        """
        times = list(self.request_times)

        if len(times) < 5:
            return 0.0   # not enough data

        # Compute inter-request gaps
        gaps = [times[i+1] - times[i] for i in range(len(times)-1)]

        if not gaps:
            return 0.0

        # Current stats
        mean = sum(gaps) / len(gaps)
        variance = sum((g - mean) ** 2 for g in gaps) / len(gaps)
        std = math.sqrt(variance) if variance > 0 else 0.0

        # Build baseline from first observations
        if not self._baseline_ready:
            self.baseline_gaps.append(std)
            if len(self.baseline_gaps) >= 10:
                b_mean = sum(self.baseline_gaps) / len(self.baseline_gaps)
                b_var  = sum(
                    (g - b_mean) ** 2 for g in self.baseline_gaps
                ) / len(self.baseline_gaps)
                self.baseline_mean   = b_mean
                self.baseline_std    = math.sqrt(b_var) if b_var > 0 else 1.0
                self._baseline_ready = True
            return 0.0   # no score until baseline is ready

        # Compare current std to baseline
        # Large deviation in either direction is suspicious
        if self.baseline_std == 0:
            return 0.0

        deviation = abs(std - self.baseline_mean) / (self.baseline_std + 0.001)

        # Normalize: deviation of 3x baseline std = score 1.0
        return min(1.0, deviation / 3.0)


    # ── Signal 4: Auth Failure Count ───────────

    def _auth_fail_score(self) -> float:
        """
        Score based on recent authentication failures.

        Only counts failures in the last WINDOW_SECONDS.

        Score = min(1.0, failures / MAX_AUTH_FAILS)

        0 failures  → 0.0
        5+ failures → 1.0
        """
        now    = time.time()
        cutoff = now - WINDOW_SECONDS

        # Count recent failures
        recent_fails = sum(
            1 for ts, _ in self.auth_failures
            if ts >= cutoff
        )

        return min(1.0, recent_fails / MAX_AUTH_FAILS)


    # ── Signal 5: Gossip / Peer Score ──────────

    def _gossip_score(self) -> float:
        """
        Score based on asymmetry with peer server's score.

        If Server B is seeing nothing unusual but Server A's
        local signals are climbing, the asymmetry amplifies
        suspicion — the attacker may be targeting A specifically.

        Also checks heartbeat timeout — if the peer has gone
        silent, that itself is a breach signal.

        Score = min(1.0, abs(local_raw - peer_score) * 2)
        Plus a bonus if heartbeat has timed out.
        """
        now = time.time()

        # Heartbeat timeout penalty
        heartbeat_penalty = 0.0
        if now - self.last_heartbeat_time > HEARTBEAT_TIMEOUT:
            heartbeat_penalty = 0.4   # silent peer is suspicious

        # Asymmetry between local and peer
        local_raw  = self.current_score
        delta      = abs(local_raw - self.peer_score)
        asymmetry  = min(1.0, delta * 2)

        return min(1.0, asymmetry + heartbeat_penalty)


    # ── Public: Record Incoming Request ────────

    def record_request(self, ip: str):
        """
        Log an incoming request.

        Call this at the start of every Flask endpoint handler.
        Updates the sliding window used by rate and timing scores.

        Args:
            ip: the IP address of the incoming request
        """
        self.request_times.append(time.time())


    def record_auth_failure(self, ip: str):
        """
        Log a failed authentication attempt.

        Call this when:
            - A share reconstruction fails
            - A ZK proof fails
            - An invalid MAC tag is received

        Args:
            ip: IP address of the failed request
        """
        self.auth_failures.append((time.time(), ip))


    def update_peer_score(self, peer_score: float):
        """
        Update the peer server's latest breach score.

        Called by the /heartbeat endpoint when Server B
        sends its current score.

        Args:
            peer_score: float in [0.0, 1.0]
        """
        self.peer_score          = max(0.0, min(1.0, peer_score))
        self.last_heartbeat_time = time.time()


    # ── Public: Compute Breach Score ───────────

    def compute(self, ip: str) -> float:
        """
        Compute the current weighted breach score.

        Combines all 5 signals with their weights:
            rate   × 0.25
            geo    × 0.30
            timing × 0.20
            auth   × 0.15
            gossip × 0.10

        Stores result in self.current_score for gossip use.

        Args:
            ip: IP of the current request (for geo scoring)

        Returns:
            float in [0.0, 1.0]
            0.0 = completely normal
            1.0 = definite breach
        """
        r = self._rate_score()
        g = self._geo_score(ip)
        t = self._timing_score()
        a = self._auth_fail_score()
        s = self._gossip_score()

        score = (
            WEIGHT_RATE   * r +
            WEIGHT_GEO    * g +
            WEIGHT_TIMING * t +
            WEIGHT_AUTH   * a +
            WEIGHT_GOSSIP * s
        )

        score = round(min(1.0, max(0.0, score)), 4)

        self.current_score = score
        self.score_history.append({
            "timestamp": time.time(),
            "score":     score,
            "signals": {
                "rate":   round(r, 4),
                "geo":    round(g, 4),
                "timing": round(t, 4),
                "auth":   round(a, 4),
                "gossip": round(s, 4),
            }
        })

        return score


    def is_breach(self, ip: str) -> bool:
        """
        Convenience method — returns True if score >= THETA.

        Usage:
            if detector.is_breach(request_ip):
                fire_ratchet()
        """
        return self.compute(ip) >= THETA


    # ── Dashboard helpers ──────────────────────

    def get_status(self) -> dict:
        """
        Return full status dict for the dashboard.

        Returns:
        {
            "current_score": float,
            "theta":         float,
            "is_breach":     bool,
            "peer_score":    float,
            "signals":       dict of latest signal values,
            "history":       list of last 20 scores
        }
        """
        # Get latest signal breakdown
        latest_signals = (
            self.score_history[-1]['signals']
            if self.score_history else {}
        )

        return {
            "current_score": self.current_score,
            "theta":         THETA,
            "is_breach":     self.current_score >= THETA,
            "peer_score":    self.peer_score,
            "signals":       latest_signals,
            "history":       list(self.score_history),
        }


    def reset(self):
        """
        Reset all signals after a successful ratchet + failover.

        After the breach is handled and Server B takes over,
        Server A's detector is reset so if it comes back
        online it starts fresh.
        """
        self.request_times.clear()
        self.auth_failures.clear()
        self.baseline_gaps.clear()
        self.baseline_mean   = None
        self.baseline_std    = None
        self._baseline_ready = False
        self.peer_score      = 0.0
        self.current_score   = 0.0
        self.score_history.clear()
        self.last_heartbeat_time = time.time()


# ─────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("Running BreachDetector self-tests...\n")

    detector = BreachDetector()

    # Test 1: clean trusted IP scores low
    for _ in range(5):
        detector.record_request("192.168.1.1")
        time.sleep(0.01)
    score = detector.compute("192.168.1.1")
    assert score < THETA, f"FAIL: trusted IP should score below theta, got {score}"
    print(f"[PASS] Trusted IP scores low: {score}")

    # Test 2: untrusted IP immediately raises geo score
    detector2 = BreachDetector()
    detector2.record_request("45.33.32.156")
    score2 = detector2.compute("45.33.32.156")
    assert score2 >= 0.30, f"FAIL: untrusted IP should score >= 0.30, got {score2}"
    print(f"[PASS] Untrusted IP raises score: {score2}")

    # Test 3: high request rate raises score
    detector3 = BreachDetector()
    for _ in range(25):
        detector3.record_request("192.168.1.1")
    score3 = detector3.compute("192.168.1.1")
    assert score3 >= 0.25, f"FAIL: high rate should raise score, got {score3}"
    print(f"[PASS] High request rate raises score: {score3}")

    # Test 4: auth failures raise score
    detector4 = BreachDetector()
    for i in range(5):
        detector4.record_auth_failure("192.168.1.1")
    score4 = detector4.compute("192.168.1.1")
    assert score4 >= 0.15, f"FAIL: auth fails should raise score, got {score4}"
    print(f"[PASS] Auth failures raise score: {score4}")

    # Test 5: peer score asymmetry raises gossip score
    detector5 = BreachDetector()
    detector5.current_score = 0.7
    detector5.update_peer_score(0.1)
    detector5.record_request("192.168.1.1")
    score5 = detector5.compute("192.168.1.1")
    assert score5 > 0.0, f"FAIL: peer asymmetry should raise score"
    print(f"[PASS] Peer score asymmetry raises score: {score5}")

    # Test 6: untrusted IP exceeds theta
    detector6 = BreachDetector()
    for _ in range(25):
        detector6.record_auth_failure("45.33.32.156")
        detector6.record_request("45.33.32.156")
    score6 = detector6.compute("45.33.32.156")
    assert score6 >= THETA, f"FAIL: combined signals should breach theta, got {score6}"
    print(f"[PASS] Combined signals exceed theta ({THETA}): {score6}")
    print(f"       is_breach() = {detector6.is_breach('45.33.32.156')}")

    # Test 7: is_breach returns correct bool
    assert detector6.is_breach("45.33.32.156") == True
    assert detector.is_breach("192.168.1.1") == False
    print(f"[PASS] is_breach() returns correct boolean")

    # Test 8: get_status returns correct structure
    status = detector6.get_status()
    assert "current_score" in status, "FAIL: missing current_score"
    assert "signals"       in status, "FAIL: missing signals"
    assert "history"       in status, "FAIL: missing history"
    assert "is_breach"     in status, "FAIL: missing is_breach"
    print(f"[PASS] get_status() returns correct structure")
    print(f"       Score: {status['current_score']}  "
          f"Breach: {status['is_breach']}")

    # Test 9: reset clears all state
    detector6.reset()
    score_after_reset = detector6.compute("192.168.1.1")
    assert score_after_reset == 0.0, \
        f"FAIL: score should be 0.0 after reset, got {score_after_reset}"
    print(f"[PASS] reset() clears all state: score={score_after_reset}")

    # Test 10: heartbeat timeout raises gossip score
    detector7 = BreachDetector()
    detector7.last_heartbeat_time = time.time() - 20  # simulate timeout
    detector7.record_request("192.168.1.1")
    score7 = detector7.compute("192.168.1.1")
    assert score7 > 0.0, "FAIL: heartbeat timeout should raise score"
    print(f"[PASS] Heartbeat timeout raises score: {score7}")

    print("\nAll tests passed. breach.py is ready.")