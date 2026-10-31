import itertools
import secrets

import pytest

import ec
from mpc import MPC
from secret_sharing import get_large_prime, reconstruct, share_value

N = ec.N


def bits_of(m, value, n):
    return [m.share((value >> i) & 1) for i in range(n)]


# ---- secret sharing -------------------------------------------------------------------
def test_shares_reconstruct():
    for value in (0, 1, 999, N - 1, secrets.randbelow(N)):
        assert reconstruct(share_value(value)) == value


def test_modulus_is_the_group_order():
    assert get_large_prime() == ec.N


def test_a_strict_subset_of_shares_does_not_determine_the_secret():
    # For fixed first two shares, every secret is possible: the third share fixes it.
    s = share_value(42)
    assert reconstruct(s[:2] + [(7 - s[0] - s[1]) % N]) == 7
    assert len(s) == 3


def test_shares_are_fresh_each_time():
    assert share_value(500) != share_value(500)


# ---- arithmetic ----------------------------------------------------------------------------
def test_linear_operations_are_local_and_correct():
    m = MPC()
    x, y = m.share(30), m.share(12)
    assert m.open(m.add(x, y), "t") == 42
    assert m.open(m.sub(x, y), "t") == 18
    assert m.open(m.mul_const(x, 5), "t") == 150
    assert m.open(m.add(x, m.constant(7)), "t") == 37
    assert m.triples_used == 0


def test_beaver_multiplication_is_correct():
    m = MPC()
    for _ in range(25):
        a, b = secrets.randbelow(N), secrets.randbelow(N)
        assert m.open(m.mul(m.share(a), m.share(b)), "t") == a * b % N


# ---- secure comparison ----------------------------------------------------------------------
def test_greater_than_is_exhaustively_correct_for_4_bit_numbers():
    m = MPC()
    for a, b in itertools.product(range(16), repeat=2):
        gt = m.greater_than(bits_of(m, a, 4), bits_of(m, b, 4))
        assert m.open(gt, "t") == (1 if a > b else 0), (a, b)


def test_greater_than_on_10_bit_numbers():
    m = MPC()
    for _ in range(40):
        a, b = secrets.randbelow(1024), secrets.randbelow(1024)
        gt = m.greater_than(bits_of(m, a, 10), bits_of(m, b, 10))
        assert m.open(gt, "t") == (1 if a > b else 0)
    for a in (0, 1, 1023):
        gt = m.greater_than(bits_of(m, a, 10), bits_of(m, a, 10))
        assert m.open(gt, "t") == 0                      # equal numbers


def test_select():
    m = MPC()
    x, y = m.share(111), m.share(222)
    assert m.open(m.select(m.share(1), x, y), "t") == 111
    assert m.open(m.select(m.share(0), x, y), "t") == 222


# ---- argmax ---------------------------------------------------------------------------------
@pytest.mark.parametrize("values", [[5], [3, 9], [9, 3], [150, 920, 600] , [0, 0, 0],
                                     [1023, 0, 1023], [7, 7, 7, 7, 8], [8, 7, 7, 7, 7]])
def test_argmax_matches_python_with_ties_going_to_the_first(values):
    m = MPC()
    winner, value = m.argmax_bits([bits_of(m, v, 10) for v in values])
    assert value == max(values)
    assert winner == values.index(max(values))


def test_argmax_random_inputs():
    for _ in range(8):
        values = [secrets.randbelow(900) for _ in range(secrets.randbelow(5) + 2)]
        m = MPC()
        winner, value = m.argmax_bits([bits_of(m, v, 10) for v in values])
        assert (winner, value) == (values.index(max(values)), max(values))


def test_argmax_of_nothing():
    assert MPC().argmax_bits([]) == (None, None)


# ---- what gets revealed -----------------------------------------------------------------------
def test_only_masked_values_and_the_result_are_ever_opened():
    values = [50, 820, 500]                         # offsets from min_bid, as the auction uses
    m = MPC()
    shared = [bits_of(m, v, 10) for v in values]
    m.opened.clear()                                # ignore the setup above (test-only opens)
    winner, value = m.argmax_bits(shared)

    outputs = [(label, v) for label, v in m.opened if label.startswith("output")]
    masked = [v for label, v in m.opened if label.startswith("beaver")]

    # Exactly one winner index plus one value per bit of the winning bid:
    assert [label for label, _ in outputs].count("output: winner index") == 1
    assert [label for label, _ in outputs].count("output: winning bid bit") == 10
    assert len(outputs) + len(masked) == len(m.opened)

    # Every intermediate value is a uniformly random mask, not a bid-sized number ...
    assert all(v > 2**128 for v in masked)
    # ... so in particular no bid and no difference between two bids is revealed.
    revealed = {v for _, v in m.opened}
    for a, b in itertools.permutations(values, 2):
        assert (a - b) % N not in revealed
    for v in values:
        if v != value:
            assert v not in {x for lbl, x in m.opened if lbl.startswith("beaver")}


def test_summary_counts():
    m = MPC()
    shared = [bits_of(m, v, 4) for v in (3, 9, 5)]
    m.argmax_bits(shared)
    s = m.summary()
    assert s["output_values_opened"] == 1 + 4
    assert s["masked_values_opened"] == 2 * s["beaver_triples"]
