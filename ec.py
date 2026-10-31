"""
ec.py - Minimal elliptic-curve arithmetic for secp256k1 (the Bitcoin curve)

Just enough for Pedersen commitments and Sigma-protocol proofs:
point addition, negation, scalar multiplication, a compact encoding, and a
"nothing up my sleeve" hash-to-curve used to derive the second generator H.

Educational code: plain Python integers, NOT constant-time, so do not use it to
protect real secrets. tests/test_ec.py cross-checks it against the `cryptography`
library, which is what makes it trustworthy enough for this project.

Points are (x, y) tuples of ints; the point at infinity is None.
"""

import hashlib

# Curve: y^2 = x^3 + 7 over GF(P), group order N, cofactor 1
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

INFINITY = None


def is_on_curve(point):
    if point is None:
        return True
    x, y = point
    return (y * y - (x * x * x + 7)) % P == 0


def point_neg(point):
    if point is None:
        return None
    x, y = point
    return (x, (-y) % P)


# --- Jacobian coordinates (X, Y, Z) represent the affine point (X/Z^2, Y/Z^3). ---
# Working in Jacobian form avoids one modular inverse per operation. Z == 0 is infinity.
_JAC_INF = (0, 1, 0)


def _jac_double(p):
    X1, Y1, Z1 = p
    if Z1 == 0 or Y1 == 0:
        return _JAC_INF
    S = 4 * X1 * Y1 * Y1 % P
    M = 3 * X1 * X1 % P
    X3 = (M * M - 2 * S) % P
    Y3 = (M * (S - X3) - 8 * pow(Y1, 4, P)) % P
    Z3 = 2 * Y1 * Z1 % P
    return (X3, Y3, Z3)


def _jac_add(p, q):
    X1, Y1, Z1 = p
    X2, Y2, Z2 = q
    if Z1 == 0:
        return q
    if Z2 == 0:
        return p
    Z1Z1 = Z1 * Z1 % P
    Z2Z2 = Z2 * Z2 % P
    U1 = X1 * Z2Z2 % P
    U2 = X2 * Z1Z1 % P
    S1 = Y1 * Z2 * Z2Z2 % P
    S2 = Y2 * Z1 * Z1Z1 % P
    if U1 == U2:
        if S1 != S2:
            return _JAC_INF          # p == -q
        return _jac_double(p)        # p == q
    H = (U2 - U1) % P
    R = (S2 - S1) % P
    H2 = H * H % P
    H3 = H * H2 % P
    V = U1 * H2 % P
    X3 = (R * R - H3 - 2 * V) % P
    Y3 = (R * (V - X3) - S1 * H3) % P
    Z3 = H * Z1 * Z2 % P
    return (X3, Y3, Z3)


def _to_jac(point):
    return _JAC_INF if point is None else (point[0], point[1], 1)


def _to_affine(p):
    X, Y, Z = p
    if Z == 0:
        return None
    zinv = pow(Z, -1, P)
    zinv2 = zinv * zinv % P
    return (X * zinv2 % P, Y * zinv2 * zinv % P)


def point_add(a, b):
    return _to_affine(_jac_add(_to_jac(a), _to_jac(b)))


def point_sub(a, b):
    return point_add(a, point_neg(b))


def scalar_mult(k, point):
    """k * point for any integer k (reduced mod the group order)."""
    k %= N
    if k == 0 or point is None:
        return None
    result = _JAC_INF
    addend = _to_jac(point)
    while k:                         # double-and-add, least significant bit first
        if k & 1:
            result = _jac_add(result, addend)
        addend = _jac_double(addend)
        k >>= 1
    return _to_affine(result)


# --- Encoding -----------------------------------------------------------------------

def encode_point(point):
    """33-byte compressed encoding (02/03 || x); a single 00 byte for infinity."""
    if point is None:
        return b"\x00"
    x, y = point
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def _lift_x(x):
    """Return a point with this x (even y), or None if x is not on the curve."""
    if not 0 <= x < P:
        return None
    rhs = (pow(x, 3, P) + 7) % P
    y = pow(rhs, (P + 1) // 4, P)    # P % 4 == 3, so this is a square root if one exists
    if y * y % P != rhs:
        return None
    return (x, y if y % 2 == 0 else P - y)


def decode_point(data):
    if data == b"\x00":
        return None
    if len(data) != 33 or data[0] not in (2, 3):
        raise ValueError("bad point encoding")
    point = _lift_x(int.from_bytes(data[1:], "big"))
    if point is None:
        raise ValueError("x is not on the curve")
    if (point[1] & 1) != (data[0] & 1):
        point = (point[0], P - point[1])
    return point


def hash_to_point(seed):
    """
    Derive a curve point from a public seed by trying x = SHA256(seed || counter) until
    it lands on the curve. Nobody can know the discrete log of the result with respect
    to G, which is exactly what Pedersen commitments need from the second generator H.
    """
    counter = 0
    while True:
        digest = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        point = _lift_x(int.from_bytes(digest, "big") % P)
        if point is not None:
            return point
        counter += 1
