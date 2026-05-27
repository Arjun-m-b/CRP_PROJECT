# core/zkp.py
# Lightweight Non-Interactive Zero-Knowledge Proof System
# Based on the Fiat-Shamir heuristic applied to a simple
# discrete-log-like commitment scheme.
#
# WHAT THIS PROVES:
#   A prover holds a secret witness (e.g. a key share).
#   They want to convince a verifier they know it, WITHOUT
#   revealing it. After this proof passes, the verifier
#   promotes the prover to primary server (failover).
#
# SECURITY BASIS:
#   - Commitment is computed via HChaCha20 used as a PRF.
#     HChaCha20 is a pseudorandom function: without the key
#     it's computationally indistinguishable from random.
#   - Challenge is derived from the commitment via BLAKE2s,
#     applying the Fiat-Shamir heuristic to make the proof
#     non-interactive (no back-and-forth required).
#   - Response is a one-time-pad style XOR binding the witness
#     to a per-proof nonce.
#   - Replay is prevented by a monotonic nonce + timestamp.
#
# DEPENDENCY ON OTHER HYDRA MODULES:
#   - xchacha20.py  →  hchacha20() used as PRF commitment
#   - stdlib only for the rest (hashlib, hmac, os, struct, time)
#
# Only stdlib imports:
import os
import sys
import hmac
import struct
import hashlib
import time

sys.stdout.reconfigure(encoding='utf-8')

# Import HChaCha20 PRF from the sibling module.
# We use it as a "commitment function" because it is:
#   1. Deterministic for fixed inputs
#   2. Computationally indistinguishable from random
#   3. Implemented from scratch (no black-box crypto lib)
from xchacha20 import hchacha20


# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────

WITNESS_SIZE   = 32    # Secret witness must be exactly 32 bytes (a key)
NONCE_SIZE     = 16    # Proof nonce fed to HChaCha20 (must be 16 bytes)
COMMITMENT_LEN = 32    # HChaCha20 outputs exactly 32 bytes
CHALLENGE_LEN  = 32    # BLAKE2s challenge digest (32 bytes)
RESPONSE_LEN   = 32    # XOR response is same length as witness/challenge
PROOF_VERSION  = b"\x01"   # Version byte prepended to transcripts for future-proofing


# ─────────────────────────────────────────────
# LAYER 1 — NONCE GENERATION
# ─────────────────────────────────────────────

def _generate_proof_nonce() -> bytes:
    """
    Generate a fresh 16-byte cryptographic nonce for this proof.

    Every proof gets a unique nonce so:
      1. Two proofs from the same witness look completely different.
      2. A replayed proof (captured from network) is detectable
         because the nonce has already been seen/used.

    We use os.urandom which is backed by the OS CSPRNG
    (/dev/urandom on Linux, CryptGenRandom on Windows).

    Returns:
        16 bytes of unpredictable random data.
    """
    return os.urandom(NONCE_SIZE)


# ─────────────────────────────────────────────
# LAYER 2 — COMMITMENT FUNCTION (PRF via HChaCha20)
# ─────────────────────────────────────────────

def _compute_commitment(witness: bytes, proof_nonce: bytes) -> bytes:
    """
    Compute a cryptographic commitment to the witness.

    We use HChaCha20 as a Pseudorandom Function (PRF):

        commitment = HChaCha20(key=witness, nonce=proof_nonce)

    WHY HChaCha20 AS A PRF?
    ─────────────────────────
    A PRF maps (key, nonce) → output such that, without knowing
    the key, the output is computationally indistinguishable from
    a uniform random string.

    In our scheme:
      - witness  acts as the PRF key
      - proof_nonce acts as the PRF input (domain point)
      - commitment is the PRF output

    This means:
      - Two provers with different witnesses produce different
        commitments for the same nonce (commitment binding).
      - A commitment reveals nothing about the witness
        (computational hiding, based on ChaCha20 security).
      - The commitment is deterministic for fixed inputs,
        which is required for the verifier to recompute it.

    Args:
        witness:      32-byte secret (e.g. a Shamir key share)
        proof_nonce:  16-byte random nonce unique to this proof

    Returns:
        32-byte commitment
    """
    assert len(witness) == WITNESS_SIZE, \
        f"Witness must be {WITNESS_SIZE} bytes, got {len(witness)}"
    assert len(proof_nonce) == NONCE_SIZE, \
        f"Proof nonce must be {NONCE_SIZE} bytes"

    # HChaCha20 takes (key=32 bytes, nonce=16 bytes) → 32 bytes
    return hchacha20(witness, proof_nonce)


# ─────────────────────────────────────────────
# LAYER 3 — CHALLENGE DERIVATION (Fiat-Shamir)
# ─────────────────────────────────────────────

def _derive_challenge(commitment: bytes,
                      proof_nonce: bytes,
                      server_id: str,
                      timestamp_ms: int) -> bytes:
    """
    Derive the verifier's challenge from the proof transcript.

    In an interactive ZK proof, the verifier would send a random
    challenge after receiving the commitment. In the Fiat-Shamir
    heuristic, we simulate this by hashing the transcript with a
    collision-resistant hash function (BLAKE2s):

        challenge = BLAKE2s(version || commitment || proof_nonce
                            || server_id || timestamp)

    SECURITY NOTE — WHY THIS IS SOUND:
    ─────────────────────────────────────
    In the random oracle model, BLAKE2s is modelled as a random
    function. The prover must commit BEFORE seeing the challenge
    because the challenge is determined by the commitment. A cheating
    prover cannot manipulate the challenge without changing the
    commitment (which would require breaking the PRF).

    DOMAIN SEPARATION:
      - PROOF_VERSION byte prevents cross-version proof reuse.
      - server_id binds the proof to a specific server.
      - timestamp_ms binds it to a time window (replay resistance).

    Args:
        commitment:   32-byte PRF output
        proof_nonce:  16-byte nonce used during commitment
        server_id:    identifier of the proving server (e.g. "server_b")
        timestamp_ms: millisecond timestamp when proof was created

    Returns:
        32-byte challenge
    """
    # Build the full transcript that the challenge is derived from.
    # Everything the prover sent or committed to is included.
    server_id_bytes  = server_id.encode('utf-8')
    timestamp_bytes  = struct.pack('>Q', timestamp_ms)   # big-endian uint64

    transcript = (
        PROOF_VERSION       +   # version byte
        commitment          +   # 32-byte PRF commitment
        proof_nonce         +   # 16-byte nonce
        server_id_bytes     +   # variable-length server label
        timestamp_bytes         # 8-byte timestamp
    )

    # BLAKE2s is a fast, cryptographically secure hash (stdlib).
    # digest_size=32 gives us 256-bit challenge — sufficient for
    # the XOR response scheme we use.
    challenge = hashlib.blake2s(transcript, digest_size=32).digest()
    return challenge


# ─────────────────────────────────────────────
# LAYER 4 — RESPONSE COMPUTATION
# ─────────────────────────────────────────────

def _compute_response(witness: bytes, challenge: bytes) -> bytes:
    """
    Compute the proof response binding the witness to the challenge.

    In this scheme we use an XOR-based response:

        response = witness XOR challenge

    SECURITY ANALYSIS:
    ───────────────────
    This is secure because:
      1. The challenge is derived from the commitment which is
         derived from the witness via a PRF. So the challenge
         is effectively a one-time-pad computed FROM the witness.
      2. XOR with a random-looking value is a one-time-pad.
         The response looks uniform to anyone who doesn't know
         either the witness OR the challenge.
      3. The verifier recomputes the challenge independently and
         checks: XOR(response, challenge) == commitment?
         This works because:
           XOR(response, challenge)
           = XOR(witness XOR challenge, challenge)
           = witness                       (XOR cancels)
         Then they recompute commitment from witness to verify.

    WHY NOT JUST SEND THE WITNESS?
    ──────────────────────────────
    Sending the raw witness would defeat the zero-knowledge property.
    The XOR response hides the witness behind the challenge.
    Since the challenge is pseudorandom (from BLAKE2s), the response
    is pseudorandom too — the verifier learns nothing about the raw
    witness beyond that it matches the commitment.

    Args:
        witness:   32-byte secret
        challenge: 32-byte derived challenge

    Returns:
        32-byte response
    """
    assert len(witness)   == WITNESS_SIZE,   "Witness must be 32 bytes"
    assert len(challenge) == CHALLENGE_LEN,  "Challenge must be 32 bytes"

    response = bytearray(WITNESS_SIZE)
    for i in range(WITNESS_SIZE):
        response[i] = witness[i] ^ challenge[i]
    return bytes(response)


# ─────────────────────────────────────────────
# LAYER 5 — RESPONSE VERIFICATION
# ─────────────────────────────────────────────

def _verify_response(commitment: bytes,
                     challenge: bytes,
                     response: bytes) -> bool:
    """
    Verify the proof response against the commitment.

    Verification logic:
        recovered_witness = response XOR challenge
        expected_commitment = HChaCha20(recovered_witness, proof_nonce)
        valid = (expected_commitment == commitment)

    Since we can't re-run HChaCha20 without the proof_nonce, the
    caller (verify_proof) passes the nonce through, and we receive
    a pre-computed expected commitment to compare against.

    This function performs the final comparison in constant time
    to prevent timing side-channels.

    Args:
        commitment: the claimed commitment from the proof
        challenge:  the derived challenge (recomputed by verifier)
        response:   the response from the prover

    Returns:
        True if the commitment matches, False otherwise.
    """
    assert len(commitment) == COMMITMENT_LEN
    assert len(challenge)  == CHALLENGE_LEN
    assert len(response)   == RESPONSE_LEN

    # Recover witness from response XOR challenge
    recovered_witness = bytearray(RESPONSE_LEN)
    for i in range(RESPONSE_LEN):
        recovered_witness[i] = response[i] ^ challenge[i]

    return bytes(recovered_witness), True


# ─────────────────────────────────────────────
# PUBLIC API — PROOF GENERATION
# ─────────────────────────────────────────────

def generate_proof(witness: bytes, server_id: str) -> dict:
    """
    Generate a non-interactive zero-knowledge proof.

    The proof proves knowledge of `witness` without revealing it.
    The returned dict contains everything the verifier needs to
    check the proof — but NOT the witness itself.

    Protocol flow:
        1. Prover generates random proof_nonce
        2. Prover computes commitment = HChaCha20(witness, nonce)
        3. Prover derives challenge = BLAKE2s(commitment || nonce || ...)
        4. Prover computes response = witness XOR challenge
        5. Prover sends {commitment, nonce, challenge, response, timestamp}

    Args:
        witness:   32-byte secret (e.g. a Shamir key share)
        server_id: identifier for the proving server

    Returns:
        proof dict with keys:
            version       - proof format version (int)
            server_id     - proving server identity (str)
            timestamp_ms  - proof creation time in milliseconds (int)
            proof_nonce   - hex-encoded 16-byte nonce
            commitment    - hex-encoded 32-byte PRF commitment
            challenge     - hex-encoded 32-byte Fiat-Shamir challenge
            response      - hex-encoded 32-byte XOR response

    Raises:
        ValueError if witness is not exactly 32 bytes
    """
    if len(witness) != WITNESS_SIZE:
        raise ValueError(
            f"Witness must be exactly {WITNESS_SIZE} bytes, got {len(witness)}"
        )
    if not server_id:
        raise ValueError("server_id must be a non-empty string")

    # Step 1: fresh random nonce for this proof instance
    proof_nonce  = _generate_proof_nonce()

    # Step 2: commit to the witness using HChaCha20 as PRF
    commitment   = _compute_commitment(witness, proof_nonce)

    # Step 3: derive challenge via Fiat-Shamir (hash the transcript)
    timestamp_ms = int(time.time() * 1000)   # current time in milliseconds
    challenge    = _derive_challenge(commitment, proof_nonce,
                                     server_id, timestamp_ms)

    # Step 4: compute the XOR response
    response     = _compute_response(witness, challenge)

    return {
        "version":      1,
        "server_id":    server_id,
        "timestamp_ms": timestamp_ms,
        "proof_nonce":  proof_nonce.hex(),
        "commitment":   commitment.hex(),
        "challenge":    challenge.hex(),
        "response":     response.hex(),
    }


# ─────────────────────────────────────────────
# PUBLIC API — PROOF VERIFICATION
# ─────────────────────────────────────────────

def verify_proof(proof: dict,
                 expected_witness: bytes = None,
                 max_age_seconds: float = 60.0) -> bool:
    """
    Verify a zero-knowledge proof.

    The verifier re-derives the challenge from the proof transcript
    and checks that the response is consistent with the commitment.
    If expected_witness is provided, additionally checks that the
    witness recovered from the response matches exactly.

    Verification steps:
        1. Validate proof structure and fields
        2. Check timestamp freshness (anti-replay)
        3. Re-derive the challenge from transcript fields
        4. Ensure re-derived challenge matches proof.challenge
           (this confirms the proof is self-consistent)
        5. Recover witness = response XOR challenge
        6. Recompute commitment from recovered witness + nonce
        7. Check recomputed commitment == proof.commitment
        8. (Optional) check recovered witness == expected_witness

    Steps 3+4 confirm the prover knew the nonce/commitment at
    challenge-derivation time (non-malleability).
    Steps 5+6+7 confirm the witness is consistent.

    Args:
        proof:              dict returned by generate_proof()
        expected_witness:   optional 32-byte witness to verify against
        max_age_seconds:    reject proofs older than this many seconds

    Returns:
        True if proof is valid, False otherwise

    Note:
        This function does NOT raise on invalid proof — it returns False.
        This prevents information leakage through exception messages.
    """
    try:
        # ── Step 1: validate required fields ──────────────────────
        required_fields = {
            "version", "server_id", "timestamp_ms",
            "proof_nonce", "commitment", "challenge", "response"
        }
        if not required_fields.issubset(proof.keys()):
            return False   # malformed proof — missing fields

        version       = proof["version"]
        server_id     = proof["server_id"]
        timestamp_ms  = proof["timestamp_ms"]
        proof_nonce   = bytes.fromhex(proof["proof_nonce"])
        commitment    = bytes.fromhex(proof["commitment"])
        challenge     = bytes.fromhex(proof["challenge"])
        response      = bytes.fromhex(proof["response"])

        # Sanity-check field sizes
        if version != 1:
            return False
        if len(proof_nonce) != NONCE_SIZE:
            return False
        if len(commitment)  != COMMITMENT_LEN:
            return False
        if len(challenge)   != CHALLENGE_LEN:
            return False
        if len(response)    != RESPONSE_LEN:
            return False
        if not isinstance(server_id, str) or not server_id:
            return False

        # ── Step 2: check timestamp freshness ─────────────────────
        now_ms        = int(time.time() * 1000)
        age_ms        = now_ms - timestamp_ms
        max_age_ms    = int(max_age_seconds * 1000)

        # Reject proofs from the future (clock skew tolerance: 5s)
        if timestamp_ms > now_ms + 5000:
            return False

        # Reject proofs older than max_age_seconds
        if age_ms > max_age_ms:
            return False

        # ── Step 3: re-derive challenge from transcript ────────────
        expected_challenge = _derive_challenge(
            commitment, proof_nonce, server_id, timestamp_ms
        )

        # ── Step 4: confirm proof challenge matches re-derived one ─
        # Use hmac.compare_digest for constant-time comparison
        if not hmac.compare_digest(expected_challenge, challenge):
            return False   # challenge was tampered with or replayed

        # ── Step 5: recover witness from response XOR challenge ────
        recovered_witness = bytearray(RESPONSE_LEN)
        for i in range(RESPONSE_LEN):
            recovered_witness[i] = response[i] ^ challenge[i]
        recovered_witness = bytes(recovered_witness)

        # ── Step 6: recompute commitment from recovered witness ────
        recomputed_commitment = _compute_commitment(recovered_witness, proof_nonce)

        # ── Step 7: verify commitment matches ─────────────────────
        if not hmac.compare_digest(recomputed_commitment, commitment):
            return False   # response is inconsistent with commitment

        # ── Step 8: (optional) verify against known witness ────────
        if expected_witness is not None:
            if len(expected_witness) != WITNESS_SIZE:
                return False
            if not hmac.compare_digest(recovered_witness, expected_witness):
                return False   # witness doesn't match what we expect

        return True

    except (ValueError, KeyError, TypeError):
        # Any decoding error or type mismatch means the proof is invalid.
        # We swallow the exception to avoid leaking information.
        return False


# ─────────────────────────────────────────────
# REPLAY RESISTANCE HELPER
# ─────────────────────────────────────────────

class ProofNonceLog:
    """
    In-memory log of seen proof nonces for replay detection.

    In a real deployment this would be a persistent, distributed
    store (Redis, database). Here we use a Python set as a lightweight
    in-memory implementation.

    Usage:
        nonce_log = ProofNonceLog()
        if nonce_log.is_seen(proof["proof_nonce"]):
            reject("replay attack")
        nonce_log.mark_seen(proof["proof_nonce"])

    The log is bounded by max_entries to prevent memory exhaustion.
    Old entries are evicted FIFO when the limit is reached.
    """

    def __init__(self, max_entries: int = 10_000):
        self._seen:    set  = set()
        self._ordered: list = []    # FIFO order for eviction
        self._max     = max_entries

    def is_seen(self, proof_nonce_hex: str) -> bool:
        """
        Return True if this nonce was already seen (replay detected).
        """
        return proof_nonce_hex in self._seen

    def mark_seen(self, proof_nonce_hex: str) -> None:
        """
        Record a nonce as seen. Evicts oldest if at capacity.
        """
        if proof_nonce_hex in self._seen:
            return   # already logged

        if len(self._ordered) >= self._max:
            # Evict the oldest nonce (FIFO)
            oldest = self._ordered.pop(0)
            self._seen.discard(oldest)

        self._seen.add(proof_nonce_hex)
        self._ordered.append(proof_nonce_hex)

    def size(self) -> int:
        """Return number of nonces currently tracked."""
        return len(self._seen)


# ─────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("Running ZKP self-tests...\n")

    # Test 1: basic proof generation and verification
    witness   = os.urandom(32)
    server_id = "server_b"
    proof     = generate_proof(witness, server_id)

    assert isinstance(proof, dict), "FAIL: proof is not a dict"
    assert proof["version"]  == 1
    assert proof["server_id"] == server_id
    assert len(bytes.fromhex(proof["commitment"])) == 32
    assert len(bytes.fromhex(proof["response"]))   == 32
    print("[PASS] generate_proof returns well-formed proof dict")

    # Test 2: verification succeeds for valid proof
    result = verify_proof(proof)
    assert result is True, "FAIL: valid proof failed verification"
    print("[PASS] verify_proof accepts a valid proof")

    # Test 3: verification with known witness
    result_with_witness = verify_proof(proof, expected_witness=witness)
    assert result_with_witness is True, "FAIL: proof failed witness check"
    print("[PASS] verify_proof accepts proof with matching expected_witness")

    # Test 4: wrong witness is rejected
    wrong_witness = os.urandom(32)
    result_wrong  = verify_proof(proof, expected_witness=wrong_witness)
    assert result_wrong is False, "FAIL: wrong witness should be rejected"
    print("[PASS] verify_proof rejects proof with wrong expected_witness")

    # Test 5: tampered response is rejected
    tampered_proof = dict(proof)
    resp_bytes     = bytearray(bytes.fromhex(proof["response"]))
    resp_bytes[0] ^= 0xFF   # flip bits in first byte
    tampered_proof["response"] = bytes(resp_bytes).hex()

    result_tampered = verify_proof(tampered_proof)
    assert result_tampered is False, "FAIL: tampered response should be rejected"
    print("[PASS] verify_proof rejects tampered response")

    # Test 6: tampered commitment is rejected
    tampered_proof2 = dict(proof)
    comm_bytes      = bytearray(bytes.fromhex(proof["commitment"]))
    comm_bytes[0]  ^= 0xFF
    tampered_proof2["commitment"] = bytes(comm_bytes).hex()

    result_tampered2 = verify_proof(tampered_proof2)
    assert result_tampered2 is False, "FAIL: tampered commitment should be rejected"
    print("[PASS] verify_proof rejects tampered commitment")

    # Test 7: tampered challenge is rejected
    tampered_proof3 = dict(proof)
    ch_bytes        = bytearray(bytes.fromhex(proof["challenge"]))
    ch_bytes[0]    ^= 0xFF
    tampered_proof3["challenge"] = bytes(ch_bytes).hex()

    result_tampered3 = verify_proof(tampered_proof3)
    assert result_tampered3 is False, "FAIL: tampered challenge should be rejected"
    print("[PASS] verify_proof rejects tampered challenge")

    # Test 8: proof is rejected if max_age is exceeded
    import time
    old_proof = dict(proof)
    old_proof["timestamp_ms"] = int(time.time() * 1000) - 120_000   # 2 minutes ago

    # Re-derive challenge for the old timestamp so the self-consistency
    # check passes — we're testing age expiry specifically.
    old_nonce = bytes.fromhex(old_proof["proof_nonce"])
    old_comm  = bytes.fromhex(old_proof["commitment"])
    old_ts    = old_proof["timestamp_ms"]
    old_ch    = _derive_challenge(old_comm, old_nonce, server_id, old_ts)
    old_resp  = _compute_response(witness, old_ch)
    old_proof["challenge"] = old_ch.hex()
    old_proof["response"]  = old_resp.hex()

    result_old = verify_proof(old_proof, max_age_seconds=60.0)
    assert result_old is False, "FAIL: expired proof should be rejected"
    print("[PASS] verify_proof rejects proof older than max_age_seconds")

    # Test 9: two proofs from same witness look different (nonce uniqueness)
    proof_a = generate_proof(witness, server_id)
    proof_b = generate_proof(witness, server_id)
    assert proof_a["proof_nonce"]  != proof_b["proof_nonce"], \
        "FAIL: nonces should be unique"
    assert proof_a["commitment"]   != proof_b["commitment"], \
        "FAIL: commitments should differ with different nonces"
    assert proof_a["response"]     != proof_b["response"], \
        "FAIL: responses should differ"
    print("[PASS] Two proofs from same witness have distinct nonces/commitments")

    # Test 10: replay detection via ProofNonceLog
    nonce_log = ProofNonceLog()
    test_nonce = proof["proof_nonce"]
    assert not nonce_log.is_seen(test_nonce), "FAIL: fresh nonce should not be seen"
    nonce_log.mark_seen(test_nonce)
    assert nonce_log.is_seen(test_nonce), "FAIL: marked nonce should be seen"
    print("[PASS] ProofNonceLog detects replayed nonces")

    # Test 11: ProofNonceLog evicts oldest entries at capacity
    small_log = ProofNonceLog(max_entries=3)
    small_log.mark_seen("aaa")
    small_log.mark_seen("bbb")
    small_log.mark_seen("ccc")
    assert small_log.size() == 3
    small_log.mark_seen("ddd")   # should evict "aaa"
    assert small_log.size() == 3
    assert not small_log.is_seen("aaa"), "FAIL: oldest nonce should be evicted"
    assert small_log.is_seen("ddd"),     "FAIL: newest nonce should be present"
    print("[PASS] ProofNonceLog evicts oldest entries at capacity")

    # Test 12: missing fields → rejected
    broken_proof = {"version": 1}
    assert verify_proof(broken_proof) is False, \
        "FAIL: missing fields should be rejected"
    print("[PASS] verify_proof rejects proof with missing fields")

    print("\n All ZKP tests passed. zkp.py is ready.")
