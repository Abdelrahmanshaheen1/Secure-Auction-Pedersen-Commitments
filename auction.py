"""
auction.py - Secure sealed-bid auction

Protocol
--------
1. Commit.   Each bidder publishes a Pedersen commitment C = bid*G + r*H.
2. Prove.    ... and a zero-knowledge proof that min_bid <= bid <= max_bid. The proof
             contains commitments C_i to the bits of (bid - min_bid).
3. Share.    The bidder secret-shares every bit (and the randomness of its commitment)
             among 3 servers. Each server can publish b_i*G + r_i*H for its shares; the
             sum over the servers must equal C_i. That check ties the shared bits to the
             proven commitment, so a bidder cannot commit to one bid and share another.
4. Compute.  The servers find the highest bid with a secure comparison on the shared bits
             (mpc.py). Only the winner and the winning bid are ever revealed.

Bids that fail the proof or the share check are rejected before they take part.
"""

import ec
from commitments import generate_commitment_params, commit_bid, generate_randomness, commitment_to_hex
from zkproofs import generate_range_proof_with_witness, verify_range_proof, range_bits
from secret_sharing import share_value, get_large_prime
from mpc import MPC

NUM_SERVERS = 3


def shares_match_commitments(bit_commitments, bit_shares, randomness_shares, params):
    """
    Server-side check that the shares each server received open the bit commitments from
    the proof: for every bit, the sum over servers of (b_ij*G + r_ij*H) equals C_i.
    Every server can publish its own term without revealing its share.
    """
    if len(bit_shares) != len(bit_commitments) or len(randomness_shares) != len(bit_commitments):
        return False
    for C_i, b_shares, r_shares in zip(bit_commitments, bit_shares, randomness_shares):
        if len(b_shares) != NUM_SERVERS or len(r_shares) != NUM_SERVERS:
            return False
        if not all(isinstance(v, int) and 0 <= v < ec.N for v in list(b_shares) + list(r_shares)):
            return False
        total = None
        for b_ij, r_ij in zip(b_shares, r_shares):
            total = ec.point_add(total, commit_bid(b_ij, r_ij, params))
        if total != C_i:
            return False
    return True


class SecureAuction:
    """Main auction system (bidders and servers are simulated in one process)."""

    def __init__(self, min_bid=100, max_bid=1000, verbose=True):
        self.min_bid = min_bid
        self.max_bid = max_bid
        self.verbose = verbose
        self.params = generate_commitment_params()
        self.n_bits = range_bits(min_bid, max_bid)

        # Only what the servers legitimately hold: public commitments and proofs, and
        # the shares. A bidder's plaintext bid and randomness are never stored here.
        self.bidders = {}       # bidder_id -> {'commitment', 'proof'}
        self.bit_shares = {}    # bidder_id -> [[share per server] for each bit]
        self.last_mpc = None

        self._say(f"🎯 Auction initialized")
        self._say(f"   Valid bid range: [{min_bid}, {max_bid}]  ({self.n_bits}-bit comparison)\n")

    def _say(self, text=""):
        if self.verbose:
            print(text)

    @staticmethod
    def _context(bidder_id):
        return f"auction/bidder/{bidder_id}".encode()

    # ---- bidder side ------------------------------------------------------------------
    def prepare_submission(self, bidder_id, bid):
        """
        What an honest bidder sends: commitment, range proof, and the secret shares.
        Raises ValueError if the bid is outside the allowed range (no valid proof exists).
        """
        randomness = generate_randomness()
        commitment = commit_bid(bid, randomness, self.params)
        proof, witness = generate_range_proof_with_witness(
            bid, randomness, self.min_bid, self.max_bid, self.params, self._context(bidder_id))
        return {
            "commitment": commitment,
            "proof": proof,
            "bit_shares": [share_value(b, ec.N, NUM_SERVERS) for b in witness["bits"]],
            "randomness_shares": [share_value(r, ec.N, NUM_SERVERS) for r in witness["randomness"]],
        }

    # ---- server side ------------------------------------------------------------------
    def submit(self, bidder_id, submission):
        """Verify a submission and, if it is valid, accept the bidder. Returns True/False."""
        if bidder_id in self.bidders:
            self._say("   ✗ Duplicate bidder id")
            return False
        try:
            commitment, proof = submission["commitment"], submission["proof"]
            bit_shares, randomness_shares = submission["bit_shares"], submission["randomness_shares"]
        except (KeyError, TypeError):
            self._say("   ✗ Malformed submission")
            return False

        if not verify_range_proof(proof, commitment, self.params, self.min_bid, self.max_bid,
                                  self._context(bidder_id)):
            self._say("   ✗ Range proof did not verify")
            return False
        try:
            bit_commitments = proof["low"]["bit_commitments"]
        except (KeyError, TypeError):
            return False
        if not shares_match_commitments(bit_commitments, bit_shares, randomness_shares, self.params):
            self._say("   ✗ Shares do not match the committed bits")
            return False

        self.bidders[bidder_id] = {"commitment": commitment, "proof": proof}
        self.bit_shares[bidder_id] = bit_shares
        return True

    def register_bidder(self, bidder_id, bid):
        """Convenience for demos: prepare an honest submission and submit it."""
        self._say(f"📝 Registering Bidder {bidder_id} with bid {bid}...")
        try:
            submission = self.prepare_submission(bidder_id, bid)
        except ValueError as error:
            self._say(f"   ✗ Invalid bid: {error}\n")
            return False
        self._say(f"   ✓ Commitment {commitment_to_hex(submission['commitment'])[:24]}...")
        self._say(f"   ✓ Range proof generated ({2 * self.n_bits} bit commitments)")
        accepted = self.submit(bidder_id, submission)
        if accepted:
            self._say("   ✓ Proof verified, shares match the commitment")
            self._say(f"   ✓ Bid split into {NUM_SERVERS} shares per bit\n")
        else:
            self._say("")
        return accepted

    def run_auction(self):
        """Run the secure comparison and announce the winner."""
        self._say("=" * 60)
        self._say("🚀 RUNNING SECURE AUCTION")
        self._say("=" * 60)

        if not self.bit_shares:
            self._say("No bidders registered!")
            return None, None

        bidder_ids = list(self.bit_shares)
        self._say(f"\n📊 Total bidders: {len(bidder_ids)}")
        self._say("🔒 Comparing bids bit by bit on secret shares...\n")

        mpc = MPC(NUM_SERVERS, ec.N)
        winner_index, offset = mpc.argmax_bits([self.bit_shares[b] for b in bidder_ids])
        self.last_mpc = mpc

        winner_id = bidder_ids[winner_index]
        winning_bid = offset + self.min_bid
        stats = mpc.summary()

        self._say("=" * 60)
        self._say("🎉 AUCTION RESULTS")
        self._say("=" * 60)
        self._say(f"🏆 Winner: Bidder {winner_id}")
        self._say(f"💰 Winning Bid: {winning_bid}")
        self._say(f"\n🔐 Opened during the run: {stats['output_values_opened']} output values "
                  f"(winner and winning bid) and {stats['masked_values_opened']} uniformly "
                  f"random Beaver values.")
        self._say("   No losing bid, and no difference between bids, was revealed.")
        self._say("=" * 60)
        return winner_id, winning_bid


def run_example_auction(bids, min_bid=100, max_bid=1000):
    """Run an example auction with given bids"""

    print("\n" + "=" * 60)
    print("🔐 SECURE SEALED-BID AUCTION")
    print("=" * 60 + "\n")

    auction = SecureAuction(min_bid, max_bid)

    for i, bid in enumerate(bids, start=1):
        auction.register_bidder(i, bid)

    return auction.run_auction()


if __name__ == "__main__":
    print("\n🔹 EXAMPLE 1: Bidders = [150, 920, 600]")
    run_example_auction([150, 920, 600])

    print("\n🔹 EXAMPLE 2: Bidders = [350, 350, 100, 300]")
    run_example_auction([350, 350, 100, 300])

    print("\n🔹 EXAMPLE 3: Bidders = [10, 999, 300, 700, 2000]")
    run_example_auction([10, 999, 300, 700, 2000])
