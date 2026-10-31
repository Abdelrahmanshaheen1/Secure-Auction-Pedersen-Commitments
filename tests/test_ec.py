import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric import ec as lib_ec

import ec


def lib_public_point(k):
    """k*G computed by the `cryptography` library (OpenSSL), as an independent reference."""
    numbers = lib_ec.derive_private_key(k, lib_ec.SECP256K1()).public_key().public_numbers()
    return (numbers.x, numbers.y)


def test_generator_is_on_curve():
    assert ec.is_on_curve(ec.G)


@pytest.mark.parametrize("k", [1, 2, 3, 7, 255, 256, 2**64 + 1, ec.N - 1, ec.N - 2])
def test_scalar_mult_matches_openssl_known_scalars(k):
    assert ec.scalar_mult(k, ec.G) == lib_public_point(k)


def test_scalar_mult_matches_openssl_random_scalars():
    for _ in range(15):
        k = secrets.randbelow(ec.N - 1) + 1
        assert ec.scalar_mult(k, ec.G) == lib_public_point(k)


def test_group_order_and_identity():
    assert ec.scalar_mult(ec.N, ec.G) is None
    assert ec.scalar_mult(0, ec.G) is None
    assert ec.point_add(ec.G, ec.point_neg(ec.G)) is None
    assert ec.point_add(None, ec.G) == ec.G
    assert ec.point_add(ec.G, None) == ec.G


def test_addition_is_commutative_associative_and_distributes():
    a, b, c = (secrets.randbelow(ec.N) for _ in range(3))
    A, B, C = (ec.scalar_mult(k, ec.G) for k in (a, b, c))
    assert ec.point_add(A, B) == ec.point_add(B, A)
    assert ec.point_add(ec.point_add(A, B), C) == ec.point_add(A, ec.point_add(B, C))
    assert ec.point_add(A, B) == ec.scalar_mult(a + b, ec.G)
    assert ec.point_add(A, A) == ec.scalar_mult(2 * a, ec.G)      # doubling path
    assert ec.scalar_mult(b, A) == ec.scalar_mult(a * b, ec.G)


def test_negative_scalars_wrap():
    assert ec.scalar_mult(-5, ec.G) == ec.point_neg(ec.scalar_mult(5, ec.G))


def test_encoding_round_trip():
    for k in (1, 2, secrets.randbelow(ec.N), ec.N - 1):
        point = ec.scalar_mult(k, ec.G)
        assert ec.decode_point(ec.encode_point(point)) == point
    assert ec.decode_point(ec.encode_point(None)) is None


def test_decoding_rejects_garbage():
    with pytest.raises(ValueError):
        ec.decode_point(b"\x05" + b"\x00" * 32)
    with pytest.raises(ValueError):
        ec.decode_point(b"\x02" + b"\x00" * 31)


def test_hash_to_point_is_deterministic_valid_and_independent_of_g():
    h1 = ec.hash_to_point(b"some seed")
    h2 = ec.hash_to_point(b"some seed")
    h3 = ec.hash_to_point(b"another seed")
    assert h1 == h2 != h3
    assert ec.is_on_curve(h1) and ec.is_on_curve(h3)
    assert h1 not in (ec.G, ec.point_neg(ec.G), None)
