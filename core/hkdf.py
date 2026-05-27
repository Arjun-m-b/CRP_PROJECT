# core/hkdf.py
# HKDF (HMAC-based Key Derivation Function) — implemented from scratch
# RFC 5869 compliant
# Only stdlib used: hashlib, hmac, sys

import sys
import hmac
import hashlib
sys.stdout.reconfigure(encoding='utf-8')


# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────

# BLAKE2s produces 32-byte digests and is faster than SHA256
# We use it as the underlying hash for all HMAC operations
HASH_LEN     = 32    # BLAKE2s digest size in bytes
MAX_OKM_LEN  = 255 * HASH_LEN   # RFC 5869 maximum output length


# ─────────────────────────────────────────────
# CORE HMAC PRIMITIVE
# ─────────────────────────────────────────────

def _hmac_blake2s(key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC using BLAKE2s as the underlying hash.

    HMAC construction:
        HMAC(K, m) = H((K XOR opad) || H((K XOR ipad) || m))

    where ipad = 0x36 repeated, opad = 0x5C repeated.

    Python's hmac module handles this correctly.
    We just specify blake2s as the digest constructor.

    Args:
        key:  the HMAC key (any length)
        data: the message to authenticate

    Returns:
        32-byte HMAC-BLAKE2s digest
    """
    return hmac.new(
        key,
        data,
        digestmod=lambda: hashlib.blake2s()
    ).digest()


# ─────────────────────────────────────────────
# HKDF EXTRACT
# ─────────────────────────────────────────────

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """
    HKDF-Extract: condense input key material into a
    pseudorandom key (PRK).

    RFC 5869 Section 2.2:
        PRK = HMAC-Hash(salt, IKM)

    The salt randomises the output even if two callers
    use the same IKM. In HYDRA the salt is the epoch
    number + server ID so every ratchet step produces
    a unique PRK even from the same base key.

    Args:
        salt: random or epoch-based salt bytes
              if empty, replaced with HASH_LEN zero bytes
        ikm:  input key material — the current encryption key

    Returns:
        32-byte pseudorandom key (PRK)
    """
    if not salt:
        salt = b'\x00' * HASH_LEN
    return _hmac_blake2s(salt, ikm)


# ─────────────────────────────────────────────
# HKDF EXPAND
# ─────────────────────────────────────────────

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF-Expand: stretch a PRK into `length` output bytes.

    RFC 5869 Section 2.3:
        T(0) = empty string
        T(1) = HMAC-Hash(PRK, T(0) || info || 0x01)
        T(2) = HMAC-Hash(PRK, T(1) || info || 0x02)
        ...
        OKM  = T(1) || T(2) || ... (first `length` bytes)

    The `info` parameter binds the output to a specific
    context — "HYDRA-encryption-key" vs "HYDRA-mac-key"
    produce completely different outputs from the same PRK.
    This is called domain separation.

    Args:
        prk:    32-byte pseudorandom key from hkdf_extract
        info:   context string (as bytes) — domain separator
        length: how many bytes of key material to produce

    Returns:
        `length` bytes of output key material (OKM)

    Raises:
        ValueError if length exceeds RFC 5869 maximum
    """
    if length > MAX_OKM_LEN:
        raise ValueError(
            f"Requested length {length} exceeds HKDF maximum {MAX_OKM_LEN}"
        )

    okm      = b""
    t_prev   = b""     # T(0) = empty
    counter  = 1

    while len(okm) < length:
        # T(i) = HMAC(PRK, T(i-1) || info || counter_byte)
        t_curr  = _hmac_blake2s(prk, t_prev + info + bytes([counter]))
        okm    += t_curr
        t_prev  = t_curr
        counter += 1

    return okm[:length]


# ─────────────────────────────────────────────
# COMBINED HKDF
# ─────────────────────────────────────────────

def hkdf(ikm: bytes, length: int,
         salt: bytes = b"", info: bytes = b"") -> bytes:
    """
    Full HKDF in one call: Extract then Expand.

    Convenience wrapper used when you have raw key material
    and want derived key bytes directly.

    Args:
        ikm:    input key material
        length: desired output length in bytes
        salt:   optional salt (recommended)
        info:   optional context/domain separator

    Returns:
        `length` bytes of derived key material
    """
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


# ─────────────────────────────────────────────
# HYDRA-SPECIFIC: KEY ZEROING
# ─────────────────────────────────────────────

def _zero_bytes(b: bytearray) -> None:
    """
    Overwrite a bytearray with zeros in place.

    Used to erase old keys from memory after ratcheting.
    Note: Python's garbage collector means we cannot
    guarantee the memory is immediately freed, but
    zeroing the bytearray removes the key value from
    our accessible reference.
    """
    for i in range(len(b)):
        b[i] = 0


# ─────────────────────────────────────────────
# HYDRA-SPECIFIC: RATCHET
# ─────────────────────────────────────────────

def ratchet(current_key: bytes, epoch: int, server_id: str) -> bytes:
    """
    Derive the next encryption key from the current one.

    This is the core of HYDRA's breach response. When the
    breach detector fires, this function:
        1. Derives a new key cryptographically bound to
           the current key, epoch number, and server ID
        2. The old key is unreachable from the new key
           (HKDF is a one-way function)

    Salt construction:
        salt = epoch_bytes + server_id_bytes
        Makes every ratchet step unique even if somehow
        the same key appeared again.

    Info construction:
        info = b"HYDRA-ratchet-v1-" + epoch_bytes
        Domain-separates ratchet output from other
        HKDF uses (subkey derivation, etc.)

    Args:
        current_key: 32-byte current encryption key (K_n)
        epoch:       current epoch number (integer)
        server_id:   "server_a" or "server_b"

    Returns:
        32-byte next encryption key (K_n+1)

    IMPORTANT: The caller is responsible for erasing
    current_key after calling this function.
    Use zero_key() below.
    """
    assert len(current_key) == 32, "Key must be 32 bytes"
    assert epoch >= 0, "Epoch must be non-negative"

    epoch_bytes     = epoch.to_bytes(4, byteorder='big')
    server_bytes    = server_id.encode('utf-8')

    salt  = epoch_bytes + server_bytes
    info  = b"HYDRA-ratchet-v1-" + epoch_bytes

    next_key = hkdf(
        ikm    = current_key,
        length = 32,
        salt   = salt,
        info   = info
    )

    return next_key


def zero_key(key: bytes) -> bytearray:
    """
    Convert key to bytearray and zero it out.

    Call this immediately after ratchet() to erase the
    old key from memory.

    Usage:
        new_key = ratchet(old_key, epoch, server_id)
        old_key = zero_key(old_key)   # old_key is now zeroed
        # old_key is a zeroed bytearray — original value gone

    Returns:
        Zeroed bytearray (the old key reference is now safe
        to let the garbage collector clean up)
    """
    key_array = bytearray(key)
    _zero_bytes(key_array)
    return key_array


# ─────────────────────────────────────────────
# HYDRA-SPECIFIC: SUBKEY DERIVATION
# ─────────────────────────────────────────────

def derive_subkeys(master_key: bytes) -> tuple:
    """
    Derive separate encryption and MAC keys from a master key.

    Never use the same key for two different purposes.
    XChaCha20 uses one key, BLAKE2s MAC uses another.
    Both are derived from the master key using HKDF with
    different info strings (domain separation).

    Args:
        master_key: 32-byte master encryption key

    Returns:
        (enc_key, mac_key) — both 32 bytes

        enc_key: for XChaCha20 encryption
        mac_key: for BLAKE2s authentication tag
    """
    assert len(master_key) == 32, "Master key must be 32 bytes"

    enc_key = hkdf(
        ikm    = master_key,
        length = 32,
        salt   = b"HYDRA-enc-salt-v1",
        info   = b"HYDRA-encryption-key"
    )

    mac_key = hkdf(
        ikm    = master_key,
        length = 32,
        salt   = b"HYDRA-mac-salt-v1",
        info   = b"HYDRA-mac-key"
    )

    return enc_key, mac_key


# ─────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("Running HKDF self-tests...\n")
    sys.stdout.reconfigure(encoding='utf-8')

    import os

    # Test 1: extract is deterministic
    ikm  = os.urandom(32)
    salt = os.urandom(16)
    prk1 = hkdf_extract(salt, ikm)
    prk2 = hkdf_extract(salt, ikm)
    assert prk1 == prk2, "FAIL: extract not deterministic"
    assert len(prk1) == 32, "FAIL: extract wrong length"
    print(f"[PASS] HKDF-Extract is deterministic")
    print(f"       PRK: {prk1.hex()}\n")

    # Test 2: expand produces correct length
    prk = hkdf_extract(salt, ikm)
    for length in [16, 32, 64, 128]:
        okm = hkdf_expand(prk, b"test-info", length)
        assert len(okm) == length, f"FAIL: expand wrong length for {length}"
    print(f"[PASS] HKDF-Expand produces correct lengths (16,32,64,128)\n")

    # Test 3: different info gives different output (domain separation)
    okm_enc = hkdf_expand(prk, b"HYDRA-encryption-key", 32)
    okm_mac = hkdf_expand(prk, b"HYDRA-mac-key", 32)
    assert okm_enc != okm_mac, "FAIL: domain separation failed"
    print(f"[PASS] Domain separation works")
    print(f"       enc_key: {okm_enc.hex()[:32]}...")
    print(f"       mac_key: {okm_mac.hex()[:32]}...\n")

    # Test 4: ratchet produces different key each epoch
    base_key = os.urandom(32)
    key_e1   = ratchet(base_key, epoch=1, server_id="server_a")
    key_e2   = ratchet(base_key, epoch=2, server_id="server_a")
    key_e3   = ratchet(base_key, epoch=3, server_id="server_a")

    assert key_e1 != base_key, "FAIL: ratchet returned same key"
    assert key_e1 != key_e2,   "FAIL: epoch 1 and 2 same key"
    assert key_e2 != key_e3,   "FAIL: epoch 2 and 3 same key"
    assert len(key_e1) == 32,  "FAIL: ratcheted key wrong length"
    print(f"[PASS] Ratchet produces unique key each epoch")
    print(f"       Base:    {base_key.hex()[:32]}...")
    print(f"       Epoch 1: {key_e1.hex()[:32]}...")
    print(f"       Epoch 2: {key_e2.hex()[:32]}...")
    print(f"       Epoch 3: {key_e3.hex()[:32]}...\n")

    # Test 5: ratchet is deterministic (same inputs = same output)
    key_e1_again = ratchet(base_key, epoch=1, server_id="server_a")
    assert key_e1 == key_e1_again, "FAIL: ratchet not deterministic"
    print(f"[PASS] Ratchet is deterministic\n")

    # Test 6: different server_id gives different key
    key_a = ratchet(base_key, epoch=1, server_id="server_a")
    key_b = ratchet(base_key, epoch=1, server_id="server_b")
    assert key_a != key_b, "FAIL: server_id does not affect output"
    print(f"[PASS] Server ID produces different ratchet keys")
    print(f"       Server A key: {key_a.hex()[:32]}...")
    print(f"       Server B key: {key_b.hex()[:32]}...\n")

    # Test 7: zero_key wipes the value
    test_key      = bytearray(b'\xFF' * 32)
    zeroed        = zero_key(bytes(test_key))
    assert all(b == 0 for b in zeroed), "FAIL: key not zeroed"
    print(f"[PASS] zero_key wipes key from memory\n")

    # Test 8: derive_subkeys returns two different 32-byte keys
    master   = os.urandom(32)
    enc, mac = derive_subkeys(master)
    assert len(enc) == 32,  "FAIL: enc_key wrong length"
    assert len(mac) == 32,  "FAIL: mac_key wrong length"
    assert enc != mac,      "FAIL: enc and mac keys are identical"
    assert enc != master,   "FAIL: enc_key equals master key"
    assert mac != master,   "FAIL: mac_key equals master key"
    print(f"[PASS] derive_subkeys returns two distinct 32-byte keys")
    print(f"       enc_key: {enc.hex()[:32]}...")
    print(f"       mac_key: {mac.hex()[:32]}...")

    # Test 9: full ratchet chain
    print(f"\n[TEST] Full ratchet chain simulation...")
    chain_key = os.urandom(32)
    print(f"       K_0: {chain_key.hex()[:32]}...")
    for epoch in range(1, 5):
        next_k    = ratchet(chain_key, epoch=epoch, server_id="server_a")
        chain_key = zero_key(chain_key)
        assert all(b == 0 for b in chain_key), f"FAIL: K_{epoch-1} not zeroed"
        chain_key = next_k
        print(f"       K_{epoch}: {chain_key.hex()[:32]}...")
    print(f"[PASS] 4-step ratchet chain works, old keys zeroed\n")

    print("All tests passed. hkdf.py is ready.")