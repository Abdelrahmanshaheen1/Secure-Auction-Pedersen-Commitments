import hashlib
import secrets

import pytest

import ec
import zkproofs
from commitments import commit_bid, generate_commitment_params, generate_randomness

params = generate_commitment_params()
MIN, MAX = 100, 1000


def make(bid, context=b"ctx", lo=MIN, hi=MAX):
    r = generate_randomness()
    C = commit_bid(bid, r, params)
    proof = zkproofs.generate_range_proof(bid, r, lo, hi, params, context)
    return C, r, proof


def verify(proof, C, context=b"ctx", lo=MIN, hi=MAX):
    return zkproofs.verify_range_proof(proof, C, params, lo, hi, context)


# ---- completeness ---------------------------------------------------------------------
@pytest.mark.parametrize("bid", [100, 101, 555, 999, 1000])
def test_valid_bids_are_accepted(bid):
    C, _, proof = make(bid)
    assert verify(proof, C)


@pytest.mark.parametrize("lo,hi,value", [(0, 1, 0), (0, 1, 1), (5, 6, 5), (5, 6, 6),
                                          (0, 7, 7), (0, 8, 8), (0, 255, 255), (1000, 1003, 1002)])
def test_small_and_power_of_two_ranges(lo, hi, value):
    C, _, proof = make(value, lo=lo, hi=hi)
    assert verify(proof, C, lo=lo, hi=hi)


# ---- the prover refuses out-of-range bids -----------------------------------------------
@pytest.mark.parametrize("bid", [-1, 0, 99, 1001, 2000])
def test_honest_prover_refuses_out_of_range(bid):
    with pytest.raises(ValueError):
        zkproofs.generate_range_proof(bid, generate_randomness(), MIN, MAX, params)


# ---- soundness: a cheating prover cannot get an out-of-range bid accepted ------------------
def forge(bid, lo=MIN, hi=MAX, context=b"ctx"):
    """
    A dishonest prover who commits to an out-of-range bid and runs the real proof
    machinery as well as it can: honest bit decomposition for the side that fits, and the
    low n bits of the (negative or oversized) difference for the side that does not.
    """
    n = zkproofs.range_bits(lo, hi)
    r = generate_randomness()
    C = commit_bid(bid, r, params)
    C_low = ec.point_sub(C, ec.scalar_mult(lo, params.G))
    C_high = ec.point_sub(ec.scalar_mult(hi, params.G), C)
    low, _, _ = zkproofs._prove_nonnegative(
        (bid - lo) % (1 << n), r, C_low, n, params, zkproofs._binding(C, lo, hi, context, "low"))
    high, _, _ = zkproofs._prove_nonnegative(
        (hi - bid) % (1 << n), -r % ec.N, C_high, n, params,
        zkproofs._binding(C, lo, hi, context, "high"))
    return C, {"min_bid": lo, "max_bid": hi, "n_bits": n, "low": low, "high": high}


@pytest.mark.parametrize("bid", [0, 99, 1001, 1023, 1050, 2000, 10**6])
def test_forged_proofs_for_out_of_range_bids_are_rejected(bid):
    C, proof = forge(bid)
    assert not verify(proof, C)


def test_the_old_forgeable_proof_format_is_rejected():
    # The previous implementation accepted any dict whose "challenge" equalled
    # SHA256(commitment:min:max), which anyone can compute for any commitment.
    C = commit_bid(2000, generate_randomness(), params)
    commitment_hex = hashlib.sha256(b"anything").hexdigest()
    challenge = hashlib.sha256(f"{commitment_hex}:{MIN}:{MAX}".encode()).hexdigest()
    old_style = {"commitment": commitment_hex, "challenge": challenge,
                 "response": "00", "min_bid": MIN, "max_bid": MAX}
    assert not verify(old_style, C)


# ---- binding to statement and context ------------------------------------------------------
def test_proof_does_not_verify_for_another_commitment():
    C, _, proof = make(500)
    other = commit_bid(500, generate_randomness(), params)
    assert not verify(proof, other)


def test_proof_is_bound_to_the_bidder_context():
    C, _, proof = make(500, context=b"bidder-1")
    assert verify(proof, C, context=b"bidder-1")
    assert not verify(proof, C, context=b"bidder-2")


def test_verifier_enforces_its_own_range_not_the_one_in_the_proof():
    # A bidder proves membership in a huge range of their own choosing.
    C, _, wide = make(5000, lo=0, hi=10**6)
    assert verify(wide, C, lo=0, hi=10**6)
    assert not verify(wide, C, lo=MIN, hi=MAX)
    # And relabelling the proof's stated range does not help either.
    relabelled = dict(wide, min_bid=MIN, max_bid=MAX)
    assert not verify(relabelled, C, lo=MIN, hi=MAX)


# ---- tampering -----------------------------------------------------------------------------
def test_tampering_with_any_part_of_the_proof_is_detected():
    C, _, proof = make(500)

    def altered(path_edit):
        import copy
        p = copy.deepcopy(proof)
        path_edit(p)
        return p

    def bump_response(p):
        e0, e1, z0, z1 = p["low"]["bit_proofs"][3]
        p["low"]["bit_proofs"][3] = (e0, e1, (z0 + 1) % ec.N, z1)

    def bump_challenge(p):
        e0, e1, z0, z1 = p["high"]["bit_proofs"][0]
        p["high"]["bit_proofs"][0] = ((e0 + 1) % ec.N, e1, z0, z1)

    def swap_bits(p):
        cs = p["low"]["bit_commitments"]
        cs[0], cs[1] = cs[1], cs[0]

    def drop_proof(p):
        p["low"]["bit_proofs"].pop()

    def shift_commitment(p):
        p["high"]["bit_commitments"][2] = ec.point_add(p["high"]["bit_commitments"][2], ec.G)

    for edit in (bump_response, bump_challenge, swap_bits, drop_proof, shift_commitment):
        assert not verify(altered(edit), C), edit.__name__


@pytest.mark.parametrize("garbage", [None, {}, {"min_bid": MIN}, [], "proof", 42,
                                      {"min_bid": MIN, "max_bid": MAX, "n_bits": 10,
                                       "low": None, "high": None},
                                      {"min_bid": -5, "max_bid": MAX, "n_bits": 10, "low": {}, "high": {}}])
def test_malformed_proofs_return_false_and_never_raise(garbage):
    C = commit_bid(500, generate_randomness(), params)
    assert verify(garbage, C) is False


def test_commitment_must_be_a_curve_point():
    _, _, proof = make(500)
    assert not verify(proof, None)
    assert not verify(proof, (1, 2))


# ---- the bit OR-proof on its own ---------------------------------------------------------------
@pytest.mark.parametrize("bit", [0, 1])
def test_bit_proof_accepts_bits(bit):
    r = generate_randomness()
    C = commit_bid(bit, r, params)
    assert zkproofs._verify_bit(C, zkproofs._prove_bit(C, bit, r, params, b"x"), params, b"x")


def test_bit_proof_cannot_be_made_for_a_non_bit():
    r = generate_randomness()
    C = commit_bid(2, r, params)                 # commits to 2, which is not a bit
    for claimed in (0, 1):
        proof = zkproofs._prove_bit(C, claimed, r, params, b"x")
        assert not zkproofs._verify_bit(C, proof, params, b"x")


# ---- zero-knowledge sanity -----------------------------------------------------------------------
def test_proofs_are_randomised_and_bit_commitments_do_not_expose_bits():
    r = generate_randomness()
    a = zkproofs.generate_range_proof(500, r, MIN, MAX, params)
    b = zkproofs.generate_range_proof(500, r, MIN, MAX, params)
    assert a["low"]["bit_commitments"] != b["low"]["bit_commitments"]
    for part in (a["low"], a["high"]):
        for c in part["bit_commitments"]:
            assert c not in (None, params.G)      # would reveal a 0 or a 1 directly
