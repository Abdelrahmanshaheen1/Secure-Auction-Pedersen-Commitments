"""
auction.py - Main Secure Auction System
"""

from commitments import generate_commitment_params, commit_bid, generate_randomness
from zkproofs import generate_range_proof, verify_range_proof
from secret_sharing import share_value, get_large_prime
from mpc import mpc_argmax


class SecureAuction:
    """Main auction system"""

    def __init__(self, min_bid=100, max_bid=1000):
        self.min_bid = min_bid
        self.max_bid = max_bid
        self.params = generate_commitment_params()
        self.p = get_large_prime()
        self.bidders = {}
        self.shares = {}

        print(f"🎯 Auction initialized")
        print(f"   Valid bid range: [{min_bid}, {max_bid}]\n")

    def register_bidder(self, bidder_id, bid):
        """Register a bidder and their bid"""

        print(f"📝 Registering Bidder {bidder_id} with bid {bid}...")

        randomness = generate_randomness()
        commitment = commit_bid(bid, randomness, self.params)
        print(f"   ✓ Commitment created")

        try:
            proof = generate_range_proof(bid, randomness, self.min_bid, self.max_bid, self.params)
            print(f"   ✓ ZK proof generated")
        except ValueError as e:
            print(f"   ✗ Invalid bid: {e}")
            return False

        is_valid = verify_range_proof(proof, commitment, self.params)
        if not is_valid:
            print(f"   ✗ Proof verification failed")
            return False
        print(f"   ✓ Proof verified")

        shares = share_value(bid, self.p)
        print(f"   ✓ Bid split into 3 shares\n")

        self.bidders[bidder_id] = {
            'bid': bid,
            'commitment': commitment,
            'proof': proof,
            'randomness': randomness
        }
        self.shares[bidder_id] = shares

        return True

    def run_auction(self):
        """Run the secure auction using MPC"""

        print("="*60)
        print("🚀 RUNNING SECURE AUCTION")
        print("="*60)

        if not self.shares:
            print("No bidders registered!")
            return None, None

        print(f"\n📊 Total bidders: {len(self.shares)}")
        print("🔒 Computing maximum bid using MPC...\n")

        bidder_ids = list(self.shares.keys())
        all_shares = [self.shares[bidder_id] for bidder_id in bidder_ids]

        max_index, max_bid = mpc_argmax(all_shares, self.p)

        if max_index is None:
            print("Error in auction computation!")
            return None, None

        winner_id = bidder_ids[max_index]

        print("="*60)
        print("🎉 AUCTION RESULTS")
        print("="*60)
        print(f"🏆 Winner: Bidder {winner_id}")
        print(f"💰 Winning Bid: {max_bid}")
        print(f"\n🔐 All other bids remain SECRET!")
        print("="*60)

        return winner_id, max_bid


def run_example_auction(bids, min_bid=100, max_bid=1000):
    """Run an example auction with given bids"""

    print("\n" + "="*60)
    print("🔐 SECURE SEALED-BID AUCTION")
    print("="*60 + "\n")

    auction = SecureAuction(min_bid, max_bid)

    for i, bid in enumerate(bids, start=1):
        auction.register_bidder(i, bid)

    winner, winning_bid = auction.run_auction()
    return winner, winning_bid


if __name__ == "__main__":
    print("\n🔹 EXAMPLE 1: Bidders = [150, 920, 600]")
    run_example_auction([150, 920, 600])

    print("\n🔹 EXAMPLE 2: Bidders = [350, 350, 100, 300]")
    run_example_auction([350, 350, 100, 300])

    print("\n🔹 EXAMPLE 3: Bidders = [10, 999, 300, 700, 2000]")
    run_example_auction([10, 999, 300, 700, 2000])
