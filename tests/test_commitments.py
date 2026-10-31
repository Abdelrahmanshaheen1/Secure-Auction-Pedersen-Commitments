import secrets

import ec
from commitments import (commit_bid, generate_commitment_params, generate_randomness,
                         verify_commitment)

params = generate_commitment_params()


def test_generators_are_distinct_valid_points():
    assert ec.is_on_curve(params.G) and ec.is_on_curve(params.H)
    assert params.H not in (params.G, ec.point_neg(params.G), None)


def test_parameters_are_deterministic_and_publicly_derivable():
    other = generate_commitment_params()
    assert other.H == params.H
    assert params.H == ec.hash_to_point(b"secure-auction/pedersen/H/v1")


def test_commitment_is_a_curve_point_not_a_hash():
    c = commit_bid(500, 12345, params)
    assert isinstance(c, tuple) and ec.is_on_curve(c)
    assert c == ec.point_add(ec.scalar_mult(500, params.G), ec.scalar_mult(12345, params.H))


def test_opens_correctly_and_rejects_wrong_openings():
    r = generate_randomness()
    c = commit_bid(500, r, params)
    assert verify_commitment(c, 500, r, params)
    assert not verify_commitment(c, 501, r, params)
    assert not verify_commitment(c, 500, r + 1, params)


def test_hiding_same_bid_gives_unrelated_commitments():
    a = commit_bid(500, generate_randomness(), params)
    b = commit_bid(500, generate_randomness(), params)
    assert a != b


def test_binding_different_bids_give_different_commitments_for_same_randomness():
    r = generate_randomness()
    assert commit_bid(500, r, params) != commit_bid(501, r, params)


def test_homomorphic_addition():
    a, b = 300, 450
    r1, r2 = generate_randomness(), generate_randomness()
    total = ec.point_add(commit_bid(a, r1, params), commit_bid(b, r2, params))
    assert total == commit_bid(a + b, (r1 + r2) % ec.N, params)


def test_zero_bid_commitment_still_hides():
    r = generate_randomness()
    c = commit_bid(0, r, params)
    assert c == ec.scalar_mult(r, params.H)
