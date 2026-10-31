import copy
import secrets

import pytest

import ec
import zkproofs
from auction import SecureAuction, run_example_auction, shares_match_commitments
from commitments import commit_bid, generate_randomness
from secret_sharing import share_value


def quiet(min_bid=100, max_bid=1000):
    return SecureAuction(min_bid, max_bid, verbose=False)


# ---- the three scenarios from the original project documentation ---------------------------
def run(bids):
    a = quiet()
    accepted = [a.register_bidder(i, b) for i, b in enumerate(bids, start=1)]
    return a, accepted, a.run_auction()


def test_normal_auction():
    _, accepted, result = run([150, 920, 600])
    assert accepted == [True, True, True]
    assert result == (2, 920)


def test_tie_goes_to_the_first_bidder():
    assert run([350, 350, 100, 300])[2] == (1, 350)


def test_invalid_bids_are_rejected_and_the_rest_still_run():
    _, accepted, result = run([10, 999, 300, 700, 2000])
    assert accepted == [False, True, True, True, False]
    assert result == (2, 999)


def test_boundary_bids_are_accepted():
    _, accepted, result = run([100, 1000, 99, 1001])
    assert accepted == [True, True, False, False]
    assert result == (2, 1000)


def test_random_auctions_pick_the_highest_valid_bid():
    for _ in range(4):
        bids = [secrets.randbelow(1200) for _ in range(4)]
        valid = [(i, b) for i, b in enumerate(bids, start=1) if 100 <= b <= 1000]
        a, _, result = run(bids)
        if not valid:
            assert result == (None, None)
        else:
            best = max(b for _, b in valid)
            first = next(i for i, b in valid if b == best)
            assert result == (first, best)


def test_no_bidders_and_single_bidder():
    assert quiet().run_auction() == (None, None)
    assert run([640])[2] == (1, 640)


def test_example_helper_prints_and_returns(capsys):
    assert run_example_auction([200, 300]) == (2, 300)
    assert "AUCTION RESULTS" in capsys.readouterr().out


# ---- cheating bidders -------------------------------------------------------------------------
def test_forged_proof_for_an_out_of_range_bid_is_rejected():
    a = quiet()
    r = generate_randomness()
    bid = 5000
    C = commit_bid(bid, r, a.params)
    n = a.n_bits
    ctx = a._context(7)
    C_low = ec.point_sub(C, ec.scalar_mult(a.min_bid, a.params.G))
    C_high = ec.point_sub(ec.scalar_mult(a.max_bid, a.params.G), C)
    low, bits, rs = zkproofs._prove_nonnegative(
        (bid - a.min_bid) % (1 << n), r, C_low, n, a.params, zkproofs._binding(C, a.min_bid, a.max_bid, ctx, "low"))
    high, _, _ = zkproofs._prove_nonnegative(
        (a.max_bid - bid) % (1 << n), -r % ec.N, C_high, n, a.params,
        zkproofs._binding(C, a.min_bid, a.max_bid, ctx, "high"))
    proof = {"min_bid": a.min_bid, "max_bid": a.max_bid, "n_bits": n, "low": low, "high": high}
    submission = {"commitment": C, "proof": proof,
                  "bit_shares": [share_value(b) for b in bits],
                  "randomness_shares": [share_value(x) for x in rs]}
    assert a.submit(7, submission) is False
    assert 7 not in a.bidders


def test_bidder_cannot_commit_to_one_bid_and_share_another():
    a = quiet()
    sub = a.prepare_submission(1, 150)
    other = a.prepare_submission(2, 900)
    cheat = dict(sub, bit_shares=other["bit_shares"], randomness_shares=other["randomness_shares"])
    assert a.submit(1, cheat) is False

    wrong_bits = copy.deepcopy(sub)
    wrong_bits["bit_shares"][0][0] = (wrong_bits["bit_shares"][0][0] + 1) % ec.N
    assert a.submit(1, wrong_bits) is False

    assert a.submit(1, sub) is True                      # the untouched submission is fine


def test_proof_cannot_be_replayed_under_another_bidder_id():
    a = quiet()
    sub = a.prepare_submission(1, 800)
    assert a.submit(2, sub) is False                     # bound to bidder 1
    assert a.submit(1, sub) is True


def test_duplicate_ids_are_rejected():
    a = quiet()
    assert a.submit(1, a.prepare_submission(1, 300))
    assert a.submit(1, a.prepare_submission(1, 900)) is False


def test_proof_for_a_wider_range_is_rejected():
    a = quiet()
    r = generate_randomness()
    bid = 5000
    C = commit_bid(bid, r, a.params)
    proof, witness = zkproofs.generate_range_proof_with_witness(bid, r, 0, 10**6, a.params, a._context(1))
    n = len(witness["bits"])
    submission = {"commitment": C, "proof": proof,
                  "bit_shares": [share_value(b) for b in witness["bits"]],
                  "randomness_shares": [share_value(x) for x in witness["randomness"]]}
    assert n != a.n_bits
    assert a.submit(1, submission) is False


@pytest.mark.parametrize("junk", [None, {}, {"commitment": None}, 5, "x"])
def test_malformed_submissions_are_rejected(junk):
    assert quiet().submit(1, junk) is False


# ---- what the servers keep ----------------------------------------------------------------------
def test_servers_do_not_store_plaintext_bids():
    a, _, _ = run([150, 920, 600])
    stored = repr(a.bidders) + repr(a.bit_shares.keys())
    for info in a.bidders.values():
        assert set(info) == {"commitment", "proof"}
    for secret in ("150", "920", "600"):
        assert f"'bid': {secret}" not in stored


def test_run_reveals_no_differences_between_bids():
    a, _, _ = run([150, 920, 600])
    revealed = {v for _, v in a.last_mpc.opened}
    offsets = [50, 820, 500]
    for x in offsets:
        for y in offsets:
            if x != y:
                assert (x - y) % ec.N not in revealed
    labels = [label for label, _ in a.last_mpc.opened]
    assert labels.count("output: winner index") == 1


def test_shares_match_check_directly():
    a = quiet()
    sub = a.prepare_submission(1, 500)
    cs = sub["proof"]["low"]["bit_commitments"]
    assert shares_match_commitments(cs, sub["bit_shares"], sub["randomness_shares"], a.params)
    assert not shares_match_commitments(cs[:-1], sub["bit_shares"], sub["randomness_shares"], a.params)
    assert not shares_match_commitments(cs, sub["bit_shares"], sub["randomness_shares"][:-1], a.params)


# ---- the enhanced demo uses the same protocol ----------------------------------------------------
def test_enhanced_demo_runs_and_agrees(capsys):
    from auction_enhanced import run_example_auction_enhanced
    assert run_example_auction_enhanced([10, 999, 300, 700, 2000]) == (2, 999)
    out = capsys.readouterr().out
    assert "BID REJECTED" in out and "NOT the losing bids" in out
