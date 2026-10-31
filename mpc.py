"""
mpc.py - Secure comparison and maximum over additively shared bits

Setting: 3 servers, each holding one additive share of every value (semi-honest, all
three needed to reconstruct anything). Linear operations (add, subtract, multiply by a
public constant) are local. Multiplying two shared values uses a Beaver triple, which is
the only place servers exchange anything: they open d = x - a and e = y - b, which are
uniformly random because a and b are secret one-time masks. Nothing else is ever opened
except the final output (winner index and winning bid).

Assumption: the Beaver triples (a, b, c = a*b) come from a trusted dealer. In a real
deployment they would be produced by an offline phase (oblivious transfer or homomorphic
encryption). This code simulates the dealer.

Bids are compared bit by bit. Revealing a difference of two bids, as a plain "subtract
the shares and open" comparison does, tells everyone bid_i - bid_j and so exposes every
losing bid once the winning bid is known. Here only the final result is opened.
"""

import secrets

import ec


class MPC:
    """A simulation of 3 servers computing on additive shares modulo p."""

    def __init__(self, num_parties=3, p=None):
        self.n = num_parties
        self.p = ec.N if p is None else p
        self.opened = []            # (label, value) for every value revealed to the servers
        self.triples_used = 0

    # ---- sharing and opening -----------------------------------------------------
    def share(self, value):
        shares = [secrets.randbelow(self.p) for _ in range(self.n - 1)]
        shares.append((value - sum(shares)) % self.p)
        return shares

    def constant(self, value):
        """A sharing of a public constant (no randomness needed)."""
        return [value % self.p] + [0] * (self.n - 1)

    def open(self, shares, label):
        """All servers reveal their shares of one value. Every call is logged."""
        value = sum(shares) % self.p
        self.opened.append((label, value))
        return value

    # ---- local (free) operations ---------------------------------------------------
    def add(self, x, y):
        return [(a + b) % self.p for a, b in zip(x, y)]

    def sub(self, x, y):
        return [(a - b) % self.p for a, b in zip(x, y)]

    def mul_const(self, x, c):
        return [(a * c) % self.p for a in x]

    # ---- multiplication with a Beaver triple ----------------------------------------
    def _triple(self):
        """Trusted dealer: shares of random a, b and of c = a*b."""
        a = secrets.randbelow(self.p)
        b = secrets.randbelow(self.p)
        self.triples_used += 1
        return self.share(a), self.share(b), self.share(a * b % self.p)

    def mul(self, x, y):
        a, b, c = self._triple()
        d = self.open(self.sub(x, a), "beaver d = x - a (masked)")
        e = self.open(self.sub(y, b), "beaver e = y - b (masked)")
        # x*y = (d + a)(e + b) = d*e + d*b + e*a + c
        z = [(c[i] + d * b[i] + e * a[i]) % self.p for i in range(self.n)]
        z[0] = (z[0] + d * e) % self.p
        return z

    # ---- comparison and selection ----------------------------------------------------
    def greater_than(self, a_bits, b_bits):
        """
        Shared bit [A > B] for two numbers given as lists of shared bits, least
        significant bit first. Scanning from the lowest bit: where the bits differ the
        higher number is the one with a 1, otherwise the answer from the lower bits stays.
        """
        assert len(a_bits) == len(b_bits) and a_bits
        one = self.constant(1)
        result = self.sub(a_bits[0], self.mul(a_bits[0], b_bits[0]))      # a0 * (1 - b0)
        for a_i, b_i in zip(a_bits[1:], b_bits[1:]):
            ab = self.mul(a_i, b_i)
            differ = self.sub(self.add(a_i, b_i), self.mul_const(ab, 2))  # a XOR b
            result = self.add(result, self.mul(differ, self.sub(a_i, result)))
        return result

    def select(self, condition, if_true, if_false):
        """if_false + condition * (if_true - if_false), without learning the condition."""
        return self.add(if_false, self.mul(condition, self.sub(if_true, if_false)))

    # ---- the auction primitive --------------------------------------------------------
    def argmax_bits(self, all_bits):
        """
        all_bits[i] is bidder i's bid as a list of shared bits (least significant first).
        Returns (winner_index, winning_value). Ties go to the earlier bidder. Only the
        winner's index and bits are opened; every comparison result stays secret-shared.
        """
        if not all_bits:
            return None, None
        best_bits = all_bits[0]
        best_index = self.constant(0)
        for i in range(1, len(all_bits)):
            beats_best = self.greater_than(all_bits[i], best_bits)
            best_bits = [self.select(beats_best, new, old)
                         for new, old in zip(all_bits[i], best_bits)]
            best_index = self.select(beats_best, self.constant(i), best_index)

        winner = self.open(best_index, "output: winner index")
        value = 0
        for position, bit in enumerate(best_bits):
            value |= self.open(bit, "output: winning bid bit") << position
        return winner, value

    def summary(self):
        masked = sum(1 for label, _ in self.opened if label.startswith("beaver"))
        outputs = [(label, v) for label, v in self.opened if label.startswith("output")]
        return {"beaver_triples": self.triples_used,
                "masked_values_opened": masked,
                "output_values_opened": len(outputs)}
