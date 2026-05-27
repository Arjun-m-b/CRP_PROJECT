# core/shamir.py
# Shamir's Secret Sharing — implemented from scratch
# No imports needed — pure Python arithmetic only

import os
import struct

# ─────────────────────────────────────────────
# PRIME FIELD
# ─────────────────────────────────────────────

# A 256-bit safe prime — all arithmetic is mod this number.
# Using a prime field ensures every number has a unique
# modular inverse, which Lagrange interpolation requires.
# This specific prime is 2^256 - 2^224 + 2^192 + 2^96 - 1
# (the NIST P-256 field prime — well studied, publicly known)
PRIME = (
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
)


# ─────────────────────────────────────────────
# CORE MATH
# ─────────────────────────────────────────────

def _mod_inverse(a: int, p: int) -> int:
    """
    Compute modular inverse of a mod p using Fermat's little theorem.

    Fermat's little theorem states:
        a^(p-1) ≡ 1 (mod p)  when p is prime
    Therefore:
        a^(p-2) ≡ a^(-1) (mod p)

    Python's built-in pow(a, p-2, p) computes this efficiently
    using fast modular exponentiation. No library needed.

    Example:
        _mod_inverse(3, 7) → 5  because 3*5 = 15 ≡ 1 (mod 7)
    """
    if a == 0:
        raise ZeroDivisionError("Cannot find inverse of 0")
    return pow(a, p - 2, p)


def _eval_polynomial(coeffs: list, x: int, p: int) -> int:
    """
    Evaluate a polynomial at point x mod p.

    Uses Horner's method for efficiency:
        f(x) = c0 + c1*x + c2*x^2 + c3*x^3
             = c0 + x*(c1 + x*(c2 + x*c3))

    This avoids computing powers of x separately.

    Args:
        coeffs: list of coefficients [c0, c1, c2, ...]
                c0 is the secret (constant term)
        x:      point to evaluate at
        p:      prime modulus

    Example:
        coeffs = [42, 7, 3]  → f(x) = 42 + 7x + 3x^2
        _eval_polynomial([42, 7, 3], 2, PRIME) → 42 + 14 + 12 = 68
    """
    result = 0
    # Horner's method: process coefficients from highest to lowest
    for coeff in reversed(coeffs):
        result = (result * x + coeff) % p
    return result


def _lagrange_interpolate(shares: list, p: int) -> int:
    """
    Reconstruct the secret at x=0 using Lagrange interpolation.

    Given k points (x1,y1), (x2,y2), ..., (xk,yk) on a polynomial,
    Lagrange interpolation finds the unique polynomial of degree k-1
    passing through all points.

    The secret is the polynomial evaluated at x=0:

        f(0) = sum over i of:
            yi * product over j≠i of:
                (0 - xj) / (xi - xj)

    All arithmetic mod p.

    Args:
        shares: list of (x, y) tuples — at least k of them
        p:      prime modulus

    Returns:
        The secret as an integer
    """
    secret = 0
    k = len(shares)

    for i in range(k):
        xi, yi = shares[i]

        # Compute Lagrange basis polynomial Li(0)
        numerator   = 1
        denominator = 1

        for j in range(k):
            if i == j:
                continue
            xj = shares[j][0]

            # numerator:   product of (0 - xj) for j≠i
            # denominator: product of (xi - xj) for j≠i
            numerator   = (numerator   * (0 - xj)) % p
            denominator = (denominator * (xi - xj)) % p

        # Li(0) = numerator * modular_inverse(denominator)
        lagrange_basis = (numerator * _mod_inverse(denominator, p)) % p

        # Add yi * Li(0) to running sum
        secret = (secret + yi * lagrange_basis) % p

    return secret


# ─────────────────────────────────────────────
# KEY CONVERSION HELPERS
# ─────────────────────────────────────────────

def _key_to_int(key: bytes) -> int:
    """
    Convert a 32-byte key to a 256-bit integer.

    Uses big-endian interpretation:
        b'\x01\x00' → 256  (not 1)

    The result is always less than 2^256, which is less than
    our PRIME, so it fits cleanly in the field.
    """
    assert len(key) == 32, "Key must be exactly 32 bytes"
    return int.from_bytes(key, byteorder='big')


def _int_to_key(n: int) -> bytes:
    """
    Convert a 256-bit integer back to a 32-byte key.
    Inverse of _key_to_int.
    """
    return n.to_bytes(32, byteorder='big')


# ─────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────

def split_key(key: bytes, n: int = 3, k: int = 2) -> list:
    """
    Split a 32-byte key into n shares where any k reconstruct it.

    This is a (k, n) threshold scheme — default is (2, 3):
        - 3 shares total
        - Any 2 can reconstruct the key
        - 1 share alone reveals nothing

    Steps:
        1. Convert key bytes to integer secret S
        2. Build polynomial: f(x) = S + a1*x + a2*x^2 + ...
           where a1...a(k-1) are random coefficients
        3. Evaluate polynomial at x=1,2,...,n to get shares

    Args:
        key: 32-byte encryption key to split
        n:   total number of shares to generate (default 3)
        k:   minimum shares needed to reconstruct (default 2)

    Returns:
        List of (x, y) tuples — the shares
        Share distribution:
            shares[0] → (1, y1) → Server A  gets S1
            shares[1] → (2, y2) → Server B  gets S2
            shares[2] → (3, y3) → Client token gets S3
    """
    assert k <= n, "Threshold k cannot exceed total shares n"
    assert k >= 2, "Threshold must be at least 2"
    assert len(key) == 32, "Key must be 32 bytes"

    secret = _key_to_int(key)

    # Build polynomial coefficients
    # coeffs[0] = secret (the value we want to recover at x=0)
    # coeffs[1..k-1] = random values in [1, PRIME-1]
    coeffs = [secret]
    for _ in range(k - 1):
        # Generate random coefficient in field
        rand_bytes = os.urandom(32)
        rand_coeff = int.from_bytes(rand_bytes, 'big') % (PRIME - 1) + 1
        coeffs.append(rand_coeff)

    # Evaluate polynomial at x = 1, 2, ..., n
    shares = []
    for x in range(1, n + 1):
        y = _eval_polynomial(coeffs, x, PRIME)
        shares.append((x, y))

    return shares


def reconstruct_key(shares: list) -> bytes:
    """
    Reconstruct the original key from k or more shares.

    Args:
        shares: list of (x, y) tuples — at least k of them
                (the same format returned by split_key)

    Returns:
        32-byte key

    Raises:
        ValueError if reconstruction produces an invalid result
    """
    if len(shares) < 2:
        raise ValueError(
            f"Need at least 2 shares to reconstruct, got {len(shares)}"
        )

    # Validate share format
    for i, share in enumerate(shares):
        if not isinstance(share, tuple) or len(share) != 2:
            raise ValueError(f"Share {i} is malformed — expected (x, y) tuple")
        x, y = share
        if not (0 < x <= 255):
            raise ValueError(f"Share {i} has invalid x coordinate: {x}")
        if not (0 <= y < PRIME):
            raise ValueError(f"Share {i} has invalid y value")

    secret_int = _lagrange_interpolate(shares, PRIME)
    return _int_to_key(secret_int)


def serialize_share(share: tuple) -> bytes:
    """
    Serialize a share to bytes for storage or transmission.

    Format: x (1 byte) + y (32 bytes) = 33 bytes total
    x is always 1-255 so fits in 1 byte.
    y is always < PRIME (256-bit) so fits in 32 bytes.
    """
    x, y = share
    x_bytes = x.to_bytes(1, 'big')
    y_bytes = y.to_bytes(32, 'big')
    return x_bytes + y_bytes


def deserialize_share(data: bytes) -> tuple:
    """
    Deserialize a share from bytes back to (x, y) tuple.
    Inverse of serialize_share.
    """
    assert len(data) == 33, f"Serialized share must be 33 bytes, got {len(data)}"
    x = int.from_bytes(data[:1], 'big')
    y = int.from_bytes(data[1:], 'big')
    return (x, y)


def encode_share_for_server(share: tuple) -> dict:
    """
    Encode a share as a dict for JSON transmission between servers.

    Returns:
        {'x': int, 'y': hex_string}

    y is hex-encoded because JSON cannot handle 256-bit integers
    reliably across all platforms.
    """
    x, y = share
    return {
        'x': x,
        'y': hex(y)
    }


def decode_share_from_server(data: dict) -> tuple:
    """
    Decode a share dict back to (x, y) tuple.
    Inverse of encode_share_for_server.
    """
    x = int(data['x'])
    y = int(data['y'], 16)
    return (x, y)


# ─────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("Running Shamir Secret Sharing self-tests...\n")

    from xchacha20 import generate_key

    # Test 1: split and reconstruct with shares 0+1 (Server A + Server B)
    key = generate_key()
    shares = split_key(key, n=3, k=2)

    print(f"Original key:  {key.hex()}")
    print(f"Share 1 (S1):  x={shares[0][0]}, y={hex(shares[0][1])[:18]}...")
    print(f"Share 2 (S2):  x={shares[1][0]}, y={hex(shares[1][1])[:18]}...")
    print(f"Share 3 (S3):  x={shares[2][0]}, y={hex(shares[2][1])[:18]}...\n")

    recovered_ab = reconstruct_key([shares[0], shares[1]])
    assert recovered_ab == key, "FAIL: S1+S2 did not reconstruct key"
    print(f"[PASS] S1 + S2 reconstructs key correctly")

    # Test 2: shares 0+2 (Server A + Client token)
    recovered_ac = reconstruct_key([shares[0], shares[2]])
    assert recovered_ac == key, "FAIL: S1+S3 did not reconstruct key"
    print(f"[PASS] S1 + S3 reconstructs key correctly")

    # Test 3: shares 1+2 (Server B + Client token)
    recovered_bc = reconstruct_key([shares[1], shares[2]])
    assert recovered_bc == key, "FAIL: S2+S3 did not reconstruct key"
    print(f"[PASS] S2 + S3 reconstructs key correctly")

    # Test 4: single share cannot reconstruct
    try:
        reconstruct_key([shares[0]])
        print("[FAIL] Single share should have raised ValueError")
    except ValueError as e:
        print(f"[PASS] Single share correctly rejected: {e}")

    # Test 5: wrong single share gives wrong key (not an error, just wrong)
    fake_share = (shares[1][0], shares[1][1] ^ 0xDEADBEEF)
    wrong_key = reconstruct_key([shares[0], fake_share])
    assert wrong_key != key, "FAIL: tampered share should not reconstruct correctly"
    print(f"[PASS] Tampered share produces wrong key (not original)")

    # Test 6: serialization roundtrip
    serialized = serialize_share(shares[0])
    assert len(serialized) == 33, "FAIL: serialized share wrong length"
    deserialized = deserialize_share(serialized)
    assert deserialized == shares[0], "FAIL: deserialization mismatch"
    print(f"[PASS] Share serialization roundtrip works")

    # Test 7: JSON encoding roundtrip
    encoded = encode_share_for_server(shares[0])
    decoded = decode_share_from_server(encoded)
    assert decoded == shares[0], "FAIL: JSON encode/decode mismatch"
    print(f"[PASS] JSON encoding roundtrip works")

    # Test 8: all three shares reconstruct correctly
    recovered_all = reconstruct_key(shares)
    assert recovered_all == key, "FAIL: all 3 shares did not reconstruct key"
    print(f"[PASS] All 3 shares reconstruct key correctly")

    print("\n All tests passed. shamir.py is ready.")