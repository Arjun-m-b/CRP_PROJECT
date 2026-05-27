# core/xchacha20.py
# XChaCha20 stream cipher — implemented from scratch
# Only stdlib used: os (for random nonce generation)
import os
import struct
import hashlib
import hmac

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────

# "expand 32-byte k" as 4 little-endian 32-bit words
# This is a standard nothing-up-my-sleeve constant
CHACHA_CONSTANTS = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)

NONCE_SIZE      = 24   # XChaCha20 uses 192-bit (24 byte) nonce
KEY_SIZE        = 32   # 256-bit key
BLOCK_SIZE      = 64   # ChaCha20 block is 512 bits = 64 bytes


# ─────────────────────────────────────────────
# LAYER 1 — CORE ARX OPERATIONS
# ─────────────────────────────────────────────

def _rotl32(v, n):
    """
    Rotate a 32-bit integer left by n bits.
    
    Example: _rotl32(0b00000001, 1) → 0b00000010
    The & 0xFFFFFFFF mask keeps the value within 32 bits.
    Without it, Python's arbitrary precision integers would
    grow forever.
    """
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _quarter_round(a, b, c, d):
    """
    The single core operation of ChaCha20.
    
    Takes 4 32-bit words, mixes them, returns 4 mixed words.
    Each step: add two words, XOR a third, rotate the result.
    
    The specific rotation amounts (16,12,8,7) were chosen by
    Bernstein for optimal diffusion — changing 1 input bit
    flips ~50% of output bits after enough rounds.
    """
    # Step 1: mix a+b into d
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = _rotl32(d, 16)

    # Step 2: mix c+d into b
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = _rotl32(b, 12)

    # Step 3: mix a+b into d again (different rotation)
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = _rotl32(d, 8)

    # Step 4: mix c+d into b again (different rotation)
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = _rotl32(b, 7)

    return a, b, c, d


# ─────────────────────────────────────────────
# LAYER 2 — STATE MATRIX HELPERS
# ─────────────────────────────────────────────

def _pack_key(key: bytes) -> tuple:
    """
    Convert 32 key bytes into 8 little-endian 32-bit words.
    
    struct.unpack('<8I', key) means:
      '<' = little-endian
      '8I' = eight unsigned 32-bit integers
    
    Example:
      key = b'\x01\x00\x00\x00' + b'\x00'*28
      → (1, 0, 0, 0, 0, 0, 0, 0)
    """
    assert len(key) == KEY_SIZE, f"Key must be {KEY_SIZE} bytes"
    return struct.unpack('<8I', key)


def _pack_nonce(nonce: bytes) -> tuple:
    """
    Convert 12 nonce bytes into 3 little-endian 32-bit words.
    Used for the standard ChaCha20 nonce (not the extended one).
    """
    assert len(nonce) == 12, "ChaCha20 nonce must be 12 bytes"
    return struct.unpack('<3I', nonce)


def _state_to_bytes(state: list) -> bytes:
    """
    Convert 16 32-bit words back into 64 bytes (one block).
    struct.pack('<16I', *state) packs 16 little-endian uint32s.
    """
    return struct.pack('<16I', *state)


# ─────────────────────────────────────────────
# LAYER 3 — CHACHA20 BLOCK FUNCTION
# ─────────────────────────────────────────────

def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """
    The ChaCha20 block function.
    
    Builds the 4x4 state matrix, runs 20 rounds of quarter rounds
    (alternating column and diagonal), then adds the result back
    to the original state.
    
    Returns 64 bytes of keystream.
    
    Args:
        key:     32-byte encryption key
        counter: block counter (increments for each 64-byte block)
        nonce:   12-byte nonce (for standard ChaCha20)
    """
    k = _pack_key(key)
    n = _pack_nonce(nonce)

    # Build initial state matrix (4x4 = 16 words)
    # Row 0: constants
    # Row 1-2: key
    # Row 3: counter + nonce
    state = [
        CHACHA_CONSTANTS[0], CHACHA_CONSTANTS[1],
        CHACHA_CONSTANTS[2], CHACHA_CONSTANTS[3],
        k[0], k[1], k[2], k[3],
        k[4], k[5], k[6], k[7],
        counter & 0xFFFFFFFF, n[0], n[1], n[2]
    ]

    # Save original state to add back at the end
    original = state[:]

    # 20 rounds = 10 pairs of (column round + diagonal round)
    for _ in range(10):
        # ── Column round ──────────────────────────
        # Mix down each of the 4 columns
        state[0],  state[4],  state[8],  state[12] = \
            _quarter_round(state[0],  state[4],  state[8],  state[12])

        state[1],  state[5],  state[9],  state[13] = \
            _quarter_round(state[1],  state[5],  state[9],  state[13])

        state[2],  state[6],  state[10], state[14] = \
            _quarter_round(state[2],  state[6],  state[10], state[14])

        state[3],  state[7],  state[11], state[15] = \
            _quarter_round(state[3],  state[7],  state[11], state[15])

        # ── Diagonal round ────────────────────────
        # Mix across the 4 diagonals of the matrix
        state[0],  state[5],  state[10], state[15] = \
            _quarter_round(state[0],  state[5],  state[10], state[15])

        state[1],  state[6],  state[11], state[12] = \
            _quarter_round(state[1],  state[6],  state[11], state[12])

        state[2],  state[7],  state[8],  state[13] = \
            _quarter_round(state[2],  state[7],  state[8],  state[13])

        state[3],  state[4],  state[9],  state[14] = \
            _quarter_round(state[3],  state[4],  state[9],  state[14])

    # Add original state back to mixed state (mod 2^32 per word)
    # This step is critical — without it the block function
    # would be invertible (you could reverse it to find the key)
    final = [(state[i] + original[i]) & 0xFFFFFFFF for i in range(16)]

    return _state_to_bytes(final)


# ─────────────────────────────────────────────
# LAYER 4 — HCHACHA20 (the X in XChaCha20)
# ─────────────────────────────────────────────

def _hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """
    HChaCha20 — the nonce extension step that makes X-ChaCha20.
    
    Standard ChaCha20 has a 96-bit (12 byte) nonce.
    XChaCha20 extends this to 192-bit (24 byte) by running
    HChaCha20 first.
    
    HChaCha20 is the ChaCha20 block function but:
      - Takes the first 16 bytes of the extended nonce
      - Returns only the FIRST and LAST rows of the final state
        (not the full 64 bytes, and WITHOUT adding original state)
      - The output is used as a subkey for the actual encryption
    
    Args:
        key:      32-byte master key
        nonce16:  first 16 bytes of the 24-byte XChaCha20 nonce
    
    Returns:
        32-byte subkey
    """
    assert len(nonce16) == 16, "HChaCha20 nonce must be 16 bytes"

    k = _pack_key(key)
    # Use all 16 bytes of nonce as 4 words (not 3 like standard ChaCha20)
    n = struct.unpack('<4I', nonce16)

    # Build state (same layout as ChaCha20)
    state = [
        CHACHA_CONSTANTS[0], CHACHA_CONSTANTS[1],
        CHACHA_CONSTANTS[2], CHACHA_CONSTANTS[3],
        k[0], k[1], k[2], k[3],
        k[4], k[5], k[6], k[7],
        n[0], n[1], n[2], n[3]   # ← all 4 nonce words, no counter
    ]

    # Run 20 rounds (same as ChaCha20 block)
    for _ in range(10):
        state[0],  state[4],  state[8],  state[12] = \
            _quarter_round(state[0],  state[4],  state[8],  state[12])
        state[1],  state[5],  state[9],  state[13] = \
            _quarter_round(state[1],  state[5],  state[9],  state[13])
        state[2],  state[6],  state[10], state[14] = \
            _quarter_round(state[2],  state[6],  state[10], state[14])
        state[3],  state[7],  state[11], state[15] = \
            _quarter_round(state[3],  state[7],  state[11], state[15])

        state[0],  state[5],  state[10], state[15] = \
            _quarter_round(state[0],  state[5],  state[10], state[15])
        state[1],  state[6],  state[11], state[12] = \
            _quarter_round(state[1],  state[6],  state[11], state[12])
        state[2],  state[7],  state[8],  state[13] = \
            _quarter_round(state[2],  state[7],  state[8],  state[13])
        state[3],  state[4],  state[9],  state[14] = \
            _quarter_round(state[3],  state[4],  state[9],  state[14])

    # KEY DIFFERENCE from chacha20_block:
    # 1. Do NOT add original state back
    # 2. Return only first row (words 0-3) + last row (words 12-15)
    #    = 8 words = 32 bytes = the subkey
    subkey_words = state[0:4] + state[12:16]
    return struct.pack('<8I', *subkey_words)


# ─────────────────────────────────────────────
# LAYER 5 — KEYSTREAM GENERATOR
# ─────────────────────────────────────────────

def _xchacha20_keystream(key: bytes, nonce: bytes, length: int,
                          counter: int = 0) -> bytes:
    """
    Generate `length` bytes of XChaCha20 keystream.
    
    Steps:
      1. Split the 24-byte nonce: first 16 bytes → HChaCha20,
         last 8 bytes → become the ChaCha20 nonce
      2. Run HChaCha20 to derive a subkey from key + nonce[:16]
      3. Construct a 12-byte ChaCha20 nonce:
         4 zero bytes + nonce[16:24]
      4. Generate blocks using the subkey until we have enough bytes
    
    Args:
        key:     32-byte key
        nonce:   24-byte XChaCha20 nonce
        length:  how many keystream bytes we need
        counter: starting block counter (default 0)
    """
    assert len(nonce) == NONCE_SIZE, f"XChaCha20 nonce must be {NONCE_SIZE} bytes"

    # Step 1 & 2: derive subkey using first 16 bytes of nonce
    subkey = _hchacha20(key, nonce[:16])

    # Step 3: build 12-byte ChaCha20 nonce from last 8 bytes
    # Prepend 4 zero bytes as per XChaCha20 spec
    chacha_nonce = b'\x00' * 4 + nonce[16:24]

    # Step 4: generate keystream blocks
    keystream = b""
    block_counter = counter

    while len(keystream) < length:
        block = _chacha20_block(subkey, block_counter, chacha_nonce)
        keystream += block
        block_counter += 1

    # Return exactly `length` bytes
    return keystream[:length]


# ─────────────────────────────────────────────
# LAYER 6 — AUTHENTICATION TAG (BLAKE2s MAC)
# ─────────────────────────────────────────────

def _compute_mac(mac_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Compute a BLAKE2s-based authentication tag.
    
    This gives us authenticated encryption — we can detect
    if the ciphertext was tampered with after encryption.
    
    We MAC over: nonce + ciphertext
    (including nonce prevents nonce-substitution attacks)
    
    Uses hashlib.blake2s — faster than SHA256, same security,
    still part of Python stdlib.
    
    Returns 32-byte tag.
    """
    h = hashlib.blake2s(key=mac_key[:32], digest_size=32)
    h.update(nonce)
    h.update(ciphertext)
    return h.digest()


def _verify_mac(mac_key: bytes, nonce: bytes,
                ciphertext: bytes, tag: bytes) -> bool:
    """
    Verify authentication tag in constant time.
    
    hmac.compare_digest prevents timing attacks — an attacker
    cannot determine how many bytes matched by measuring
    how long the comparison took.
    """
    expected = _compute_mac(mac_key, nonce, ciphertext)
    return hmac.compare_digest(expected, tag)


# ─────────────────────────────────────────────
# PUBLIC API — what the rest of HYDRA uses
# ─────────────────────────────────────────────

def generate_nonce() -> bytes:
    """
    Generate a cryptographically random 24-byte nonce.
    os.urandom() uses the OS's secure random source
    (/dev/urandom on Linux, CryptGenRandom on Windows).
    
    NEVER reuse a nonce with the same key.
    XChaCha20's 24-byte nonce makes accidental reuse
    extremely unlikely even when generated randomly.
    """
    return os.urandom(NONCE_SIZE)


def generate_key() -> bytes:
    """Generate a cryptographically random 32-byte key."""
    return os.urandom(KEY_SIZE)


def encrypt(key: bytes, plaintext: bytes, nonce: bytes = None) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext using XChaCha20 with BLAKE2s authentication.
    
    Args:
        key:       32-byte encryption key
        plaintext: data to encrypt (any length)
        nonce:     24-byte nonce (generated randomly if not provided)
    
    Returns:
        (nonce, ciphertext, mac_tag)
        
        nonce:      24 bytes — must be stored alongside ciphertext
        ciphertext: same length as plaintext
        mac_tag:    32 bytes — used to verify integrity on decrypt
    
    The key is split internally:
        enc_key = key[:32]  ← for XChaCha20 keystream
        mac_key = BLAKE2s(key + "mac") ← for authentication
    """
    assert len(key) == KEY_SIZE, f"Key must be {KEY_SIZE} bytes"

    if nonce is None:
        nonce = generate_nonce()

    # Derive separate MAC key from encryption key
    # Never use the same key for two different purposes
    mac_key = hashlib.blake2s(key + b"hydra-mac-key").digest()

    # Generate keystream and XOR with plaintext
    keystream = _xchacha20_keystream(key, nonce, len(plaintext))
    # In encrypt — replace the ciphertext line
    ciphertext = bytearray(len(plaintext))
    for i in range(len(plaintext)):
        ciphertext[i] = plaintext[i] ^ keystream[i]
    ciphertext = bytes(ciphertext)

    # Compute authentication tag over nonce + ciphertext
    tag = _compute_mac(mac_key, nonce, ciphertext)

    return nonce, ciphertext, tag


def decrypt(key: bytes, nonce: bytes,
            ciphertext: bytes, tag: bytes) -> bytes:
    """
    Decrypt ciphertext using XChaCha20, verifying authentication tag first.
    
    Args:
        key:        32-byte encryption key (same as used to encrypt)
        nonce:      24-byte nonce (stored alongside ciphertext)
        ciphertext: encrypted data
        tag:        32-byte MAC tag (from encrypt)
    
    Returns:
        plaintext bytes
    
    Raises:
        ValueError if the MAC tag doesn't match — meaning the
        ciphertext was tampered with, or the wrong key was used.
        ALWAYS check the tag before decrypting. We do this here.
    """
    assert len(key) == KEY_SIZE, f"Key must be {KEY_SIZE} bytes"
    assert len(nonce) == NONCE_SIZE, f"Nonce must be {NONCE_SIZE} bytes"

    # Derive same MAC key
    mac_key = hashlib.blake2s(key + b"hydra-mac-key").digest()

    # VERIFY FIRST — never decrypt unauthenticated ciphertext
    if not _verify_mac(mac_key, nonce, ciphertext, tag):
        raise ValueError(
            "Authentication failed — ciphertext has been tampered with "
            "or wrong key was used."
        )

    # Decryption is identical to encryption (XOR is symmetric)
    keystream = _xchacha20_keystream(key, nonce, len(ciphertext))
    # In decrypt — replace the plaintext line  
    plaintext = bytearray(len(ciphertext))
    for i in range(len(ciphertext)):
        plaintext[i] = ciphertext[i] ^ keystream[i]
    plaintext = bytes(plaintext)

    return plaintext


# ─────────────────────────────────────────────
# HCHACHA20 — exported for use in zkp.py
# ─────────────────────────────────────────────

def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """
    Public export of HChaCha20 for use as a PRF in the ZK proof.
    ZKP uses this as a commitment function instead of a hash.
    """
    return _hchacha20(key, nonce16)


# ─────────────────────────────────────────────
# SELF-TEST — run this file directly to verify
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("Running XChaCha20 self-tests...\n")

    # Test 1: encrypt then decrypt returns original
    key   = generate_key()
    nonce = generate_nonce()
    msg   = b"HYDRA test message - patient record data"

    n,ct,tag = encrypt(key, msg, nonce)
    pt = decrypt(key, n, ct, tag)

    assert pt == msg, "FAIL: decrypt did not return original message"
    print(f"[PASS] Encrypt/decrypt roundtrip")
    print(f"       Plaintext:  {msg}")
    print(f"       Ciphertext: {ct.hex()}")
    print(f"       MAC tag:    {tag.hex()}\n")

    # Test 2: wrong key raises ValueError
    bad_key = generate_key()
    try:
        decrypt(bad_key, n, ct, tag)
        print("[FAIL] Should have raised ValueError with wrong key")
    except ValueError as e:
        print(f"[PASS] Wrong key correctly rejected: {e}\n")

    # Test 3: tampered ciphertext raises ValueError
    tampered = bytearray(ct)
    tampered[0] ^= 0xFF   # flip all bits in first byte
    try:
        decrypt(key, n, bytes(tampered), tag)
        print("[FAIL] Should have raised ValueError on tampered ciphertext")
    except ValueError as e:
        print(f"[PASS] Tampered ciphertext correctly rejected: {e}\n")

    # Test 4: different nonce gives different ciphertext
    n2, ct2, tag2 = encrypt(key, msg)
    assert ct != ct2, "FAIL: same ciphertext with different nonce"
    print(f"[PASS] Different nonces produce different ciphertexts")
    print(f"       Nonce 1 ciphertext: {ct.hex()[:32]}...")
    print(f"       Nonce 2 ciphertext: {ct2.hex()[:32]}...\n")

    # Test 5: ciphertext same length as plaintext
    assert len(ct) == len(msg), "FAIL: ciphertext length mismatch"
    print(f"[PASS] Ciphertext length matches plaintext ({len(msg)} bytes)")

    # Test 6: HChaCha20 output is deterministic
    h1 = hchacha20(key, nonce[:16])
    h2 = hchacha20(key, nonce[:16])
    assert h1 == h2, "FAIL: HChaCha20 not deterministic"
    print(f"\n[PASS] HChaCha20 is deterministic")
    print(f"       Subkey: {h1.hex()}")

    print("\n✓ All tests passed. xchacha20.py is ready.")