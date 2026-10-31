"""
auction_enhanced.py - Auction with step-by-step output, timings and an interactive mode

Same protocol as auction.py (real Pedersen commitments, a real range proof, secure
comparison on shared bits); this file adds measurements and a more detailed printout.
"""

import time

import ec
from auction import SecureAuction, NUM_SERVERS
from commitments import commitment_to_hex
from mpc import MPC


class EnhancedSecureAuction(SecureAuction):
    """SecureAuction plus per-bidder timings and a detailed report."""

    def __init__(self, min_bid=100, max_bid=1000, auction_name="Secure Auction"):
        print("\n" + "═" * 70)
        print(f"{'🔐 ' + auction_name.upper() + ' 🔐':^70}")
        print("═" * 70)
        super().__init__(min_bid, max_bid, verbose=False)
        self.auction_name = auction_name
        self.registration_times = []
        self.rejected_bids = 0
        print(f"🎯 {auction_name} initialized")
        print(f"   Valid bid range: [{min_bid}, {max_bid}] ({self.n_bits}-bit comparison)")
        print(f"   Cryptography: Pedersen commitments on {self.params.curve}, bit-decomposition")
        print(f"   range proofs, {NUM_SERVERS}-server MPC with Beaver triples\n")

    def register_bidder(self, bidder_id, bid, show_details=True):
        start = time.time()
        if show_details:
            print(f"\n{'─' * 70}\n📝 Registering Bidder {bidder_id}\n{'─' * 70}")

        try:
            submission = self.prepare_submission(bidder_id, bid)
        except ValueError as error:
            self.rejected_bids += 1
            if show_details:
                print(f"✗ Step 1/3: no valid range proof exists\n  └─ Reason: {error}\n  └─ Status: ❌ BID REJECTED")
            return False

        if show_details:
            print("✓ Step 1/3: commitment and range proof created")
            print(f"  └─ Commitment: {commitment_to_hex(submission['commitment'])[:40]}...")
            print(f"  └─ Proving: {self.min_bid} ≤ bid ≤ {self.max_bid} without revealing the bid")

        if not self.submit(bidder_id, submission):
            self.rejected_bids += 1
            if show_details:
                print("✗ Step 2/3: verification failed\n  └─ Status: ❌ BID REJECTED")
            return False

        elapsed = time.time() - start
        self.registration_times.append(elapsed)
        if show_details:
            print("✓ Step 2/3: range proof verified, shares match the committed bits")
            print(f"✓ Step 3/3: each bit split into {NUM_SERVERS} shares, one per server")
            print(f"⏱️  Prove + verify + share check: {elapsed * 1000:.0f}ms")
            print(f"✅ Bidder {bidder_id} registered")
        return True

    def run_auction(self):
        print("\n" + "═" * 70 + "\n🚀 AUCTION COMPUTATION PHASE\n" + "═" * 70)
        if not self.bit_shares:
            print("\n❌ No valid bidders registered!")
            return None, None

        print(f"\n📊 Statistics: {len(self.bit_shares)} bidders registered, "
              f"{self.rejected_bids} rejected")
        if self.registration_times:
            avg = sum(self.registration_times) / len(self.registration_times)
            print(f"   Average registration time: {avg * 1000:.0f}ms")

        bidder_ids = list(self.bit_shares)
        mpc = MPC(NUM_SERVERS, ec.N)
        start = time.time()
        winner_index, offset = mpc.argmax_bits([self.bit_shares[b] for b in bidder_ids])
        mpc_time = time.time() - start
        self.last_mpc = mpc

        winner_id, winning_bid = bidder_ids[winner_index], offset + self.min_bid
        stats = mpc.summary()

        print("\n" + "═" * 70 + "\n🎉 AUCTION RESULTS\n" + "═" * 70)
        print(f"  🏆 Winner:       Bidder {winner_id}")
        print(f"  💰 Winning bid:  {winning_bid}")
        print(f"  👥 Bidders:      {len(bidder_ids)}")
        print(f"\n⏱️  MPC computation: {mpc_time * 1000:.0f}ms "
              f"({stats['beaver_triples']} secure multiplications)")
        print("\n🔐 What was revealed:")
        print(f"   • the winner and the winning bid ({stats['output_values_opened']} opened values)")
        print(f"   • {stats['masked_values_opened']} values that are uniformly random one-time masks")
        print("   • NOT the losing bids, and NOT the differences between bids")
        print("═" * 70)
        return winner_id, winning_bid

    def display_summary(self):
        """Public view: commitments only. The bids themselves are not stored anywhere."""
        print("\n" + "═" * 70 + "\n📋 REGISTERED BIDDERS (public view)\n" + "═" * 70)
        print(f"\n{'Bidder ID':<12} {'Status':<14} {'Commitment':<44}")
        print("─" * 70)
        for bidder_id, info in self.bidders.items():
            print(f"{str(bidder_id):<12} {'✅ Accepted':<14} "
                  f"{commitment_to_hex(info['commitment'])[:40] + '...':<44}")
        print("═" * 70)


def interactive_mode():
    """Let the user type bids into their own auction."""
    print("\n" + "🎮" * 35 + "\nINTERACTIVE AUCTION MODE\n" + "🎮" * 35)
    try:
        min_bid = int(input("Enter minimum bid (default 100): ") or "100")
        max_bid = int(input("Enter maximum bid (default 1000): ") or "1000")
        num_bidders = int(input("How many bidders? (2-10): ") or "3")
        if not 2 <= num_bidders <= 10:
            print("⚠️  Using 3 bidders")
            num_bidders = 3
        if not 0 <= min_bid < max_bid:
            raise ValueError("need 0 <= min < max")
    except (ValueError, EOFError):
        print("⚠️  Using defaults: min=100, max=1000, bidders=3")
        min_bid, max_bid, num_bidders = 100, 1000, 3

    auction = EnhancedSecureAuction(min_bid, max_bid, "Interactive Auction")
    print(f"\n💰 Enter {num_bidders} bids:")
    for i in range(1, num_bidders + 1):
        try:
            auction.register_bidder(i, int(input(f"  Bidder {i}'s bid: ")), show_details=False)
        except (ValueError, EOFError):
            print("    ✗ Invalid input, skipping")
            continue
        print("    ✓ Registered" if i in auction.bidders else "    ✗ Rejected (outside the allowed range)")

    if auction.bit_shares:
        auction.display_summary()
        auction.run_auction()
    else:
        print("\n❌ No valid bids to auction!")


def run_example_auction_enhanced(bids, min_bid=100, max_bid=1000, name="Example Auction"):
    auction = EnhancedSecureAuction(min_bid, max_bid, name)
    print(f"\n{'═' * 70}\n📝 REGISTRATION PHASE\n{'═' * 70}")
    for i, bid in enumerate(bids, start=1):
        auction.register_bidder(i, bid, show_details=True)
    auction.display_summary()
    return auction.run_auction()


if __name__ == "__main__":
    print("\n" + "█" * 70 + "\nENHANCED SECURE SEALED-BID AUCTION SYSTEM\n" + "█" * 70)

    print("\n\n🔹 EXAMPLE 1: Standard Auction")
    run_example_auction_enhanced([150, 920, 600], name="Standard Auction")

    print("\n\n🔹 EXAMPLE 2: Tie-Breaking Auction")
    run_example_auction_enhanced([350, 350, 100, 300], name="Tie-Breaking Auction")

    print("\n\n🔹 EXAMPLE 3: Security Test (Invalid Bids)")
    run_example_auction_enhanced([10, 999, 300, 700, 2000], name="Security Test Auction")

    print("\n\n" + "█" * 70)
    try:
        answer = input("\n🎮 Want to try INTERACTIVE MODE? (yes/no): ")
    except EOFError:
        answer = "no"
    if answer.strip().lower() in ("yes", "y"):
        interactive_mode()

    print("\n" + "█" * 70 + "\nALL DEMONSTRATIONS COMPLETE ✅\n" + "█" * 70)
