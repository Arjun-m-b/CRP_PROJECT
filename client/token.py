"""
HYDRA :: token.py
=================
Simulates a hardware security token (HSM) in software.

A hardware token in a real PKI system stores key material in tamper-resistant
hardware (e.g. a YubiKey, TPM, or smart-card). Here we emulate that contract:

  - The "token file" is a JSON blob on disk, AES-replaced by XChaCha20.
  - The passphrase is stretched via PBKDF2-HMAC-SHA256 into a 256-bit key.
  - The token blob contains one Shamir share + a derived HMAC signing key.
  - Every outbound request is HMAC-SHA256 signed with that signing key so the
    server can verify the caller owns a valid share without seeing the share.
  - A MAC over the entire ciphertext detects any tampering with the token file.

Cryptographic decisions documented inline throughout.
"""

import os
import json
import hmac
import time
import struct
import hashlib
import base64
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants — no magic numbers
# ---------------------------------------------------------------------------

# XChaCha20 uses a 192-bit (24-byte) nonce, compared to ChaCha20's 96-bit.
# The extended nonce makes random nonce collision negligible even across
# billions of messages, which matters for long-lived token files.
XCHACHA20_NONCE_BYTES: int = 24

# ChaCha20/XChaCha20 key is always 256 bits (32 bytes).
CHACHA20_KEY_BYTES: int = 32

# PBKDF2 iteration count.  NIST SP 800-132 recommends ≥10 000; we use 600 000
# to match current OWASP guidance for password hashing (2024).
PBKDF2_ITERATIONS: int = 600_000

# Salt for PBKDF2 — stored in the token file alongside the ciphertext.
PBKDF2_SALT_BYTES: int = 32

# HMAC tag size (SHA-256 output = 32 bytes).
HMAC_TAG_BYTES: int = 32

# Poly1305 tag size — used for the ChaCha20-Poly1305 MAC.
POLY1305_TAG_BYTES: int = 16

# Default token file location (can be overridden by callers).
DEFAULT_TOKEN_PATH: Path = Path.home() / ".hydra" / "token.bin"

# Domain separation label used in HKDF-like key derivation for the signing key.
SIGNING_KEY_INFO: bytes = b"HYDRA-v1-request-signing-key"

# Version tag written at the top of every token file so we can detect
# format changes and refuse to decrypt tokens from a different version.
TOKEN_FORMAT_VERSION: int = 1


# ---------------------------------------------------------------------------
# Low-level XChaCha20 implementation
# (same core as the server-side primitive — reproduced here so the client
# has zero dependency on the server package and can run stand-alone)
# ---------------------------------------------------------------------------

def _chacha20_quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    """
    The ChaCha20 quarter-round function (RFC 8439 §2.1).

    Mutates four 32-bit words of `state` in-place using four ARX operations
    (Add, Rotate, XOR).  All arithmetic is modular 2^32 — we mask with
    0xFFFFFFFF after every addition.

    This is the *only* non-linear mixing primitive in ChaCha20; the entire
    cipher is built from 20 applications of this function.
    """
    MASK32 = 0xFFFFFFFF

    state[a] = (state[a] + state[b]) & MASK32
    state[d] ^= state[a]
    state[d] = ((state[d] << 16) | (state[d] >> 16)) & MASK32

    state[c] = (state[c] + state[d]) & MASK32
    state[b] ^= state[c]
    state[b] = ((state[b] << 12) | (state[b] >> 20)) & MASK32

    state[a] = (state[a] + state[b]) & MASK32
    state[d] ^= state[a]
    state[d] = ((state[d] << 8) | (state[d] >> 24)) & MASK32

    state[c] = (state[c] + state[d]) & MASK32
    state[b] ^= state[c]
    state[b] = ((state[b] << 7) | (state[b] >> 25)) & MASK32


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """
    Produce one 64-byte ChaCha20 keystream block (RFC 8439 §2.3).

    State layout (16 × 32-bit words):
      0–3   : constants "expa nd 3 2-by te k"
      4–11  : key (256 bits = 8 words)
      12    : block counter
      13–15 : nonce (96 bits = 3 words)

    We run 20 rounds (10 column-rounds + 10 diagonal-rounds) then add the
    initial state back to produce the output block.  The add-back prevents
    inverting the permutation to recover the key.
    """
    CONSTANTS = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]

    # Unpack 256-bit key into 8 little-endian 32-bit words.
    key_words = list(struct.unpack_from("<8I", key))

    # Unpack 96-bit nonce into 3 little-endian 32-bit words.
    nonce_words = list(struct.unpack_from("<3I", nonce))

    # Build initial state.
    initial: list[int] = (
        CONSTANTS
        + key_words
        + [counter & 0xFFFFFFFF]
        + nonce_words
    )

    working = initial[:]  # mutable copy for the 20 mixing rounds

    # 10 double-rounds = 20 quarter-rounds total.
    for _ in range(10):
        # Column rounds
        _chacha20_quarter_round(working, 0, 4, 8, 12)
        _chacha20_quarter_round(working, 1, 5, 9, 13)
        _chacha20_quarter_round(working, 2, 6, 10, 14)
        _chacha20_quarter_round(working, 3, 7, 11, 15)
        # Diagonal rounds
        _chacha20_quarter_round(working, 0, 5, 10, 15)
        _chacha20_quarter_round(working, 1, 6, 11, 12)
        _chacha20_quarter_round(working, 2, 7, 8, 13)
        _chacha20_quarter_round(working, 3, 4, 9, 14)

    # Add initial state back (prevents state inversion).
    MASK32 = 0xFFFFFFFF
    output_words = [(working[i] + initial[i]) & MASK32 for i in range(16)]

    return struct.pack("<16I", *output_words)


def _hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """
    HChaCha20 sub-key derivation (draft-irtf-cfrg-xchacha §2.2).

    Takes the first 16 bytes of the XChaCha20 nonce plus the key and returns
    a 32-byte sub-key.  This sub-key is then used with the remaining 8 bytes
    of the nonce as the real ChaCha20 key+nonce, giving us the extended nonce.

    This is what makes XChaCha20 safe with random 192-bit nonces — the nonce
    space is so large that we cannot accidentally reuse one.
    """
    CONSTANTS = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]

    key_words = list(struct.unpack_from("<8I", key))
    nonce_words = list(struct.unpack_from("<4I", nonce16))

    state: list[int] = CONSTANTS + key_words + nonce_words

    # Same 20 mixing rounds as ChaCha20 block — but we do NOT add back the
    # initial state; we extract sub-key from words 0–3 and 12–15.
    for _ in range(10):
        _chacha20_quarter_round(state, 0, 4, 8, 12)
        _chacha20_quarter_round(state, 1, 5, 9, 13)
        _chacha20_quarter_round(state, 2, 6, 10, 14)
        _chacha20_quarter_round(state, 3, 7, 11, 15)
        _chacha20_quarter_round(state, 0, 5, 10, 15)
        _chacha20_quarter_round(state, 1, 6, 11, 12)
        _chacha20_quarter_round(state, 2, 7, 8, 13)
        _chacha20_quarter_round(state, 3, 4, 9, 14)

    sub_key = struct.pack("<4I", *state[:4]) + struct.pack("<4I", *state[12:16])
    return sub_key


def xchacha20_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """
    XChaCha20 stream cipher encryption (in-place XOR of keystream).

    Steps:
      1. Derive a sub-key via HChaCha20(key, nonce[:16]).
      2. Build a ChaCha20 nonce from  0x00000000 || nonce[16:24].
      3. Generate keystream blocks and XOR with plaintext.

    XChaCha20 is identical to ChaCha20 except for the extended nonce and the
    HChaCha20 sub-key derivation step.  Both encryption and decryption use
    the same function (XOR is its own inverse).
    """
    if len(key) != CHACHA20_KEY_BYTES:
        raise ValueError(f"Key must be {CHACHA20_KEY_BYTES} bytes")
    if len(nonce) != XCHACHA20_NONCE_BYTES:
        raise ValueError(f"XChaCha20 nonce must be {XCHACHA20_NONCE_BYTES} bytes")

    # Step 1 — derive sub-key from first 16 bytes of nonce.
    sub_key = _hchacha20(key, nonce[:16])

    # Step 2 — build the 12-byte ChaCha20 nonce: 4 zero bytes + last 8 nonce bytes.
    chacha20_nonce = b"\x00\x00\x00\x00" + nonce[16:24]

    # Step 3 — stream-encrypt by XOR with keystream blocks.
    keystream = bytearray()
    block_counter = 1  # counter starts at 1, reserving block 0 for Poly1305

    for i in range(0, len(plaintext), 64):
        block = _chacha20_block(sub_key, block_counter, chacha20_nonce)
        keystream.extend(block)
        block_counter += 1

    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
    return ciphertext


# Decryption is identical to encryption (XOR is self-inverse).
xchacha20_decrypt = xchacha20_encrypt


# ---------------------------------------------------------------------------
# PBKDF2 passphrase stretching
# ---------------------------------------------------------------------------

def _derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    """
    Stretch a human-chosen passphrase into a 256-bit AES/XChaCha20 key.

    We use PBKDF2-HMAC-SHA256 because:
      - It is a NIST-approved KDF (SP 800-132).
      - The iteration count (PBKDF2_ITERATIONS = 600 000) makes brute-force
        expensive even on GPU clusters.
      - It is available in Python's standard library (hashlib.pbkdf2_hmac),
        avoiding any external dependency.

    The salt is randomly generated at token-creation time and stored in the
    token file.  Without the salt, an attacker cannot pre-compute a rainbow
    table across all possible passphrases.
    """
    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=passphrase.encode("utf-8"),
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        dklen=CHACHA20_KEY_BYTES,
    )


# ---------------------------------------------------------------------------
# HKDF-Expand for signing-key derivation
# ---------------------------------------------------------------------------

def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF-Expand (RFC 5869 §2.3).

    Given a pseudo-random key (prk) and context-specific info, derive an
    output key material (OKM) of the requested byte length.

    We use this to derive a *separate* HMAC signing key from the encryption
    key rather than reusing the same key for both purposes.  Key separation
    prevents an attacker from mounting a chosen-ciphertext attack that
    manipulates the MAC.
    """
    hash_len = 32  # SHA-256 output
    n = (length + hash_len - 1) // hash_len  # number of blocks needed

    okm = b""
    t = b""  # T(0) = empty string
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), "sha256").digest()
        okm += t

    return okm[:length]


# ---------------------------------------------------------------------------
# Token file structure
# ---------------------------------------------------------------------------
#
# Layout (JSON after decryption):
#   {
#     "version":     1,
#     "share_hex":   "<hex-encoded Shamir share bytes>",
#     "share_index": <int>,        # which share (1..n) this token holds
#     "created_at":  <unix timestamp>,
#     "node_id":     "<identifier of the HYDRA node this share was issued for>"
#   }
#
# On-disk binary layout (little-endian where applicable):
#   [4 bytes]  magic  "HYDT"
#   [1 byte ]  format version
#   [32 bytes] PBKDF2 salt
#   [24 bytes] XChaCha20 nonce
#   [32 bytes] HMAC-SHA256 authentication tag  (over version+salt+nonce+ciphertext)
#   [N bytes ] XChaCha20 ciphertext of the JSON blob
#
# The HMAC tag is computed *after* encryption (Encrypt-then-MAC), which is the
# provably secure construction (as opposed to MAC-then-Encrypt).

MAGIC_BYTES: bytes = b"HYDT"


def _pack_token_file(
    salt: bytes,
    nonce: bytes,
    auth_tag: bytes,
    ciphertext: bytes,
) -> bytes:
    """Assemble the on-disk binary token file from its components."""
    version_byte = bytes([TOKEN_FORMAT_VERSION])
    return MAGIC_BYTES + version_byte + salt + nonce + auth_tag + ciphertext


def _unpack_token_file(data: bytes) -> tuple[int, bytes, bytes, bytes, bytes]:
    """
    Parse binary token file back into components.

    Returns (version, salt, nonce, auth_tag, ciphertext).
    Raises ValueError on malformed input.
    """
    if len(data) < 4 + 1 + 32 + 24 + 32:
        raise ValueError("Token file is too short to be valid")

    magic = data[:4]
    if magic != MAGIC_BYTES:
        raise ValueError(f"Invalid magic bytes: {magic!r} — not a HYDRA token file")

    offset = 4
    version = data[offset]
    offset += 1

    if version != TOKEN_FORMAT_VERSION:
        raise ValueError(
            f"Unsupported token format version {version} "
            f"(expected {TOKEN_FORMAT_VERSION})"
        )

    salt = data[offset : offset + 32]
    offset += 32
    nonce = data[offset : offset + 24]
    offset += 24
    auth_tag = data[offset : offset + 32]
    offset += 32
    ciphertext = data[offset:]

    return version, salt, nonce, auth_tag, ciphertext


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def save_share(
    share_bytes: bytes,
    share_index: int,
    node_id: str,
    passphrase: str,
    token_path: Path = DEFAULT_TOKEN_PATH,
) -> None:
    """
    Encrypt and persist a Shamir share to the local token file.

    Parameters
    ----------
    share_bytes  : Raw bytes of the Shamir share (output of the SSS module).
    share_index  : The share's index (1-based) so the server can reconstruct
                   which shares it has received.
    node_id      : Human-readable identifier of the HYDRA server node this
                   share was issued for (e.g. "server_a").
    passphrase   : User-chosen passphrase used to encrypt the token file.
    token_path   : File system path for the token file.

    Security notes
    --------------
    - A fresh random salt and nonce are generated on every save, ensuring that
      re-saving the same share with the same passphrase produces a different
      ciphertext (probabilistic encryption).
    - The HMAC tag covers the entire ciphertext + its header so that any byte
      flip in the file is detected before decryption (Encrypt-then-MAC).
    - The directory is created with mode 0o700 (owner read/write/execute only)
      and the token file itself is 0o600 (owner read/write only).
    """
    # Build the plaintext JSON payload.
    payload = json.dumps(
        {
            "version": TOKEN_FORMAT_VERSION,
            "share_hex": share_bytes.hex(),
            "share_index": share_index,
            "created_at": int(time.time()),
            "node_id": node_id,
        },
        separators=(",", ":"),  # compact JSON — no whitespace
    ).encode("utf-8")

    # Generate fresh random salt and nonce.
    salt = os.urandom(PBKDF2_SALT_BYTES)
    nonce = os.urandom(XCHACHA20_NONCE_BYTES)

    # Stretch passphrase → encryption key.
    enc_key = _derive_key_from_passphrase(passphrase, salt)

    # Encrypt the payload.
    ciphertext = xchacha20_encrypt(enc_key, nonce, payload)

    # Derive a *separate* HMAC key via HKDF-Expand to avoid key reuse.
    mac_key = _hkdf_expand(enc_key, SIGNING_KEY_INFO, CHACHA20_KEY_BYTES)

    # Compute Encrypt-then-MAC tag over version byte + salt + nonce + ciphertext.
    version_byte = bytes([TOKEN_FORMAT_VERSION])
    mac_input = version_byte + salt + nonce + ciphertext
    auth_tag = hmac.new(mac_key, mac_input, "sha256").digest()

    # Pack everything into the binary token file.
    token_data = _pack_token_file(salt, nonce, auth_tag, ciphertext)

    # Write to disk with restrictive permissions.
    token_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    token_path.write_bytes(token_data)
    token_path.chmod(0o600)

    print(f"[token] Share #{share_index} saved to {token_path}")


def load_share(
    passphrase: str,
    token_path: Path = DEFAULT_TOKEN_PATH,
) -> dict:
    """
    Load and decrypt the Shamir share from the local token file.

    Returns a dict with keys:
        share_bytes  : bytes  — the raw Shamir share
        share_index  : int    — which share this is (1-based)
        node_id      : str    — the associated HYDRA server node ID
        created_at   : int    — Unix timestamp of token creation

    Raises
    ------
    FileNotFoundError  : token file does not exist
    ValueError         : token file is malformed or the HMAC check fails
                         (possible passphrase error *or* file tampering)

    Security note
    -------------
    We deliberately do NOT distinguish "wrong passphrase" from "tampered file"
    in the error message.  An attacker observing the error cannot tell whether
    they guessed the passphrase incorrectly or corrupted the file — both look
    the same to the caller.
    """
    if not token_path.exists():
        raise FileNotFoundError(f"No token file found at {token_path}")

    raw = token_path.read_bytes()
    _version, salt, nonce, stored_tag, ciphertext = _unpack_token_file(raw)

    # Stretch passphrase → encryption key (same derivation as save_share).
    enc_key = _derive_key_from_passphrase(passphrase, salt)

    # Re-derive MAC key.
    mac_key = _hkdf_expand(enc_key, SIGNING_KEY_INFO, CHACHA20_KEY_BYTES)

    # Verify the HMAC *before* decrypting — fail fast on tampering.
    version_byte = bytes([TOKEN_FORMAT_VERSION])
    mac_input = version_byte + salt + nonce + ciphertext
    expected_tag = hmac.new(mac_key, mac_input, "sha256").digest()

    # Constant-time comparison prevents timing side-channels that could leak
    # information about how many bytes of the tag matched.
    if not hmac.compare_digest(expected_tag, stored_tag):
        raise ValueError(
            "Token authentication failed — wrong passphrase or file tampered"
        )

    # Decrypt the payload.
    plaintext = xchacha20_decrypt(enc_key, nonce, ciphertext)

    payload = json.loads(plaintext.decode("utf-8"))

    # Reconstruct share bytes from hex.
    share_bytes = bytes.fromhex(payload["share_hex"])

    return {
        "share_bytes": share_bytes,
        "share_index": payload["share_index"],
        "node_id": payload["node_id"],
        "created_at": payload["created_at"],
    }


def sign_request(
    request_body: bytes,
    passphrase: str,
    token_path: Path = DEFAULT_TOKEN_PATH,
) -> str:
    """
    Produce an HMAC-SHA256 signature over an outbound request body.

    The signature is computed using a key derived from the token's share bytes
    via HKDF-Expand.  This means:
      - The server can verify the caller holds a legitimate share.
      - The share itself is never transmitted — only its HMAC derivative.
      - Each request body produces a different signature (replay protection
        is handled by including a timestamp or nonce in the request body
        before calling this function).

    Returns
    -------
    hex-encoded HMAC-SHA256 signature string.

    Usage
    -----
    >>> sig = sign_request(body_bytes, passphrase="my-passphrase")
    >>> headers["X-HYDRA-Sig"] = sig
    """
    token = load_share(passphrase, token_path)
    share_bytes: bytes = token["share_bytes"]

    # Derive a per-request signing key from the share material.
    # We use the share bytes as the HKDF PRK so that only the holder of the
    # share can produce valid signatures.
    signing_key = _hkdf_expand(share_bytes, SIGNING_KEY_INFO, CHACHA20_KEY_BYTES)

    signature = hmac.new(signing_key, request_body, "sha256").digest()
    return signature.hex()


# ---------------------------------------------------------------------------
# Convenience: token info for display
# ---------------------------------------------------------------------------

def token_info(
    passphrase: str,
    token_path: Path = DEFAULT_TOKEN_PATH,
) -> dict:
    """
    Return human-readable metadata about the stored token (no share bytes).

    Useful for `hydra status` output — shows the token exists and is valid
    without exposing the raw share material.
    """
    token = load_share(passphrase, token_path)
    created = time.strftime(
        "%Y-%m-%d %H:%M:%S UTC", time.gmtime(token["created_at"])
    )
    return {
        "share_index": token["share_index"],
        "node_id": token["node_id"],
        "created_at": created,
        "token_path": str(token_path),
        "status": "valid",
    }
