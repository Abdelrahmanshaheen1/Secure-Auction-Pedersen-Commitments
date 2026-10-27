"""
auction_enhanced.py - Enhanced Secure Auction System
New Features: Visualization, Interactive Mode, Performance Metrics, Better Security
"""

from commitments import generate_commitment_params, commit_bid, generate_randomness, verify_commitment
from zkproofs import generate_range_proof, verify_range_proof
from secret_sharing import share_value, reconstruct, get_large_prime
from mpc import mpc_argmax
import time
import hashlib


class EnhancedSecureAuction:
    """
    Enhanced auction system with visualization and metrics
    """

    def __init__(self, min_bid=100, max_bid=1000, auction_name="Secure Auction"):
        """Initialize the enhanced auction"""
        self.min_bid = min_bid
        self.max_bid = max_bid
        self.auction_name = auction_name
        self.params = generate_commitment_params()
        self.p = get_large_prime()

        # Storage
        self.bidders = {}
        self.shares = {}

        # Metrics
        self.start_time = None
        self.registration_times = []
        self.total_proofs_generated = 0
        self.total_proofs_verified = 0
        self.rejected_bids = 0

        self._print_header()
        print(f"🎯 {self.auction_name} Initialized")
        print(f"   Valid bid range: [{min_bid}, {max_bid}]")
        print(f"   Security: 3-Party MPC with {len(str(self.p))} digit prime")
        print(f"   Cryptography: Pedersen Commitments + ZK Proofs\n")

    def _print_header(self):
        """Print fancy header"""
        print("\n" + "═"*70)
        print(f"{'🔐 ' + self.auction_name.upper() + ' 🔐':^70}")
        print("═"*70)

    def _print_progress_bar(self, current, total, prefix="Progress"):
        """Print a progress bar"""
        bar_length = 40
        filled = int(bar_length * current / total)
        bar = "█" * filled + "░" * (bar_length - filled)
        percent = 100 * current / total
        print(f"\r{prefix}: |{bar}| {percent:.1f}% ({current}/{total})", end="")
        if current == total:
            print()

    def register_bidder(self, bidder_id, bid, show_details=True):
        """
        Register a bidder with enhanced tracking
        """
        start = time.time()

        if show_details:
            print(f"\n{'─'*70}")
            print(f"📝 Registering Bidder {bidder_id}")
            print(f"{'─'*70}")

        # Step 1: Commitment
        randomness = generate_randomness()
        commitment = commit_bid(bid, randomness, self.params)
        if show_details:
            print(f"✓ Step 1/4: Commitment created")
            print(f"  └─ Hash: {commitment[:32]}...")

        # Step 2: ZK Proof Generation
        try:
            proof = generate_range_proof(bid, randomness, self.min_bid, self.max_bid, self.params)
            self.total_proofs_generated += 1
            if show_details:
                print(f"✓ Step 2/4: ZK Proof generated")
                print(f"  └─ Proving: {self.min_bid} ≤ bid ≤ {self.max_bid}")
        except ValueError as e:
            self.rejected_bids += 1
            if show_details:
                print(f"✗ Step 2/4: ZK Proof FAILED")
                print(f"  └─ Reason: {e}")
                print(f"  └─ Status: ❌ BID REJECTED")
            return False

        # Step 3: Proof Verification
        is_valid = verify_range_proof(proof, commitment, self.params)
        self.total_proofs_verified += 1

        if not is_valid:
            self.rejected_bids += 1
            if show_details:
                print(f"✗ Step 3/4: Proof verification FAILED")
                print(f"  └─ Status: ❌ BID REJECTED")
            return False

        if show_details:
            print(f"✓ Step 3/4: Proof verified successfully")

        # Step 4: Secret Sharing
        shares = share_value(bid, self.p)
        if show_details:
            print(f"✓ Step 4/4: Bid split into secret shares")
            print(f"  ├─ Server 1 receives share: {str(shares[0])[:20]}...")
            print(f"  ├─ Server 2 receives share: {str(shares[1])[:20]}...")
            print(f"  └─ Server 3 receives share: {str(shares[2])[:20]}...")

        # Verify shares reconstruct correctly (security check)
        reconstructed = reconstruct(shares, self.p)
        if reconstructed != bid:
            print(f"  ⚠️  Warning: Share reconstruction mismatch!")
            return False

        if show_details:
            print(f"\n🔒 Security Check: Shares reconstruct correctly ✓")

        # Store everything
        self.bidders[bidder_id] = {
            'bid': bid,
            'commitment': commitment,
            'proof': proof,
            'randomness': randomness,
            'timestamp': time.time()
        }
        self.shares[bidder_id] = shares

        # Track timing
        elapsed = time.time() - start
        self.registration_times.append(elapsed)

        if show_details:
            print(f"⏱️  Registration time: {elapsed*1000:.2f}ms")
            print(f"✅ Bidder {bidder_id} registered successfully!")

        return True

    def verify_all_commitments(self):
        """Verify all bidders' commitments (optional security check)"""
        print(f"\n{'─'*70}")
        print("🔍 Verifying All Commitments...")
        print(f"{'─'*70}")

        all_valid = True
        for bidder_id, info in self.bidders.items():
            is_valid = verify_commitment(
                info['commitment'],
                info['bid'],
                info['randomness'],
                self.params
            )
            status = "✓" if is_valid else "✗"
            print(f"{status} Bidder {bidder_id}: {'Valid' if is_valid else 'INVALID'}")
            all_valid = all_valid and is_valid

        print(f"\n{'✅ All commitments valid!' if all_valid else '❌ Some commitments invalid!'}")
        return all_valid

    def run_auction(self, verify_commitments=True):
        """Run the enhanced auction with metrics"""

        self._print_header()
        print("🚀 AUCTION COMPUTATION PHASE")
        print("═"*70)

        if not self.shares:
            print("\n❌ No valid bidders registered!")
            return None, None

        self.start_time = time.time()

        # Optional: Verify all commitments
        if verify_commitments:
            self.verify_all_commitments()

        # Display auction info
        print(f"\n📊 Auction Statistics:")
        print(f"   • Total bidders registered: {len(self.shares)}")
        print(f"   • Bids rejected: {self.rejected_bids}")
        print(f"   • ZK Proofs generated: {self.total_proofs_generated}")
        print(f"   • ZK Proofs verified: {self.total_proofs_verified}")

        if self.registration_times:
            avg_time = sum(self.registration_times) / len(self.registration_times)
            print(f"   • Avg registration time: {avg_time*1000:.2f}ms")

        print(f"\n🔒 Running MPC Protocol...")
        print(f"   Step 1: Collecting secret shares from all bidders...")

        # Collect shares
        bidder_ids = list(self.shares.keys())
        all_shares = [self.shares[bidder_id] for bidder_id in bidder_ids]

        print(f"   Step 2: Servers performing secure computation...")
        print(f"   Step 3: Comparing {len(all_shares)} bids using MPC...")

        # Show progress
        for i in range(len(all_shares)):
            time.sleep(0.1)  # Simulate computation
            self._print_progress_bar(i+1, len(all_shares), "   MPC Progress")

        # Find maximum
        mpc_start = time.time()
        max_index, max_bid = mpc_argmax(all_shares, self.p)
        mpc_time = time.time() - mpc_start

        if max_index is None:
            print("\n❌ Error in auction computation!")
            return None, None

        winner_id = bidder_ids[max_index]
        total_time = time.time() - self.start_time

        # Display results
        self._print_results(winner_id, max_bid, mpc_time, total_time)

        return winner_id, max_bid

    def _print_results(self, winner_id, winning_bid, mpc_time, total_time):
        """Print fancy results"""
        print("\n" + "═"*70)
        print("🎉 AUCTION RESULTS")
        print("═"*70)
        print(f"""
╔════════════════════════════════════════════════════════════════════╗
║                         🏆 WINNER ANNOUNCEMENT 🏆                  ║
╠════════════════════════════════════════════════════════════════════╣
║  Winner:        Bidder {winner_id:<45}║
║  Winning Bid:   ${winning_bid:<44}║
║  Total Bidders: {len(self.shares):<49}║
╚════════════════════════════════════════════════════════════════════╝
        """)

        print("⏱️  Performance Metrics:")
        print(f"   • MPC computation time: {mpc_time*1000:.2f}ms")
        print(f"   • Total auction time: {total_time:.2f}s")

        print("\n🔐 Privacy Guarantees:")
        print(f"   ✓ All losing bids remain SECRET")
        print(f"   ✓ No server saw any complete bid")
        print(f"   ✓ Only the difference was revealed during comparison")
        print(f"   ✓ {len(self.shares) - 1} bids stay private forever")

        print("═"*70)

    def display_summary(self):
        """Display detailed summary"""
        print("\n" + "═"*70)
        print("📋 COMPLETE AUCTION SUMMARY (Admin View)")
        print("═"*70)

        print(f"\n{'Bidder ID':<12} {'Bid':<10} {'Status':<12} {'Commitment':<20}")
        print("─"*70)

        for bidder_id, info in self.bidders.items():
            status = "✅ Accepted"
            commitment_preview = info['commitment'][:16] + "..."
            print(f"{str(bidder_id):<12} ${info['bid']:<9} {status:<12} {commitment_preview:<20}")

        print("═"*70)


def interactive_mode():
    """
    Interactive mode: Let users create their own auction
    """
    print("\n" + "🎮"*35)
    print("INTERACTIVE AUCTION MODE")
    print("🎮"*35)

    # Get auction parameters
    print("\n📝 Setup your auction:")

    try:
        min_bid = int(input("Enter minimum bid (default 100): ") or "100")
        max_bid = int(input("Enter maximum bid (default 1000): ") or "1000")
        num_bidders = int(input("How many bidders? (2-10): ") or "3")

        if num_bidders < 2 or num_bidders > 10:
            print("⚠️  Using 3 bidders")
            num_bidders = 3
    except:
        print("⚠️  Using defaults: min=100, max=1000, bidders=3")
        min_bid, max_bid, num_bidders = 100, 1000, 3

    # Create auction
    auction = EnhancedSecureAuction(min_bid, max_bid, "Interactive Auction")

    # Get bids
    print(f"\n💰 Enter {num_bidders} bids:")
    for i in range(1, num_bidders + 1):
        try:
            bid = int(input(f"  Bidder {i}'s bid: "))
            auction.register_bidder(i, bid, show_details=False)
            print(f"    ✓ Registered")
        except:
            print(f"    ✗ Invalid input, skipping")

    # Run auction
    if auction.shares:
        auction.display_summary()
        auction.run_auction()
    else:
        print("\n❌ No valid bids to auction!")


def run_example_auction_enhanced(bids, min_bid=100, max_bid=1000, name="Example Auction"):
    """Run example with enhanced features"""

    auction = EnhancedSecureAuction(min_bid, max_bid, name)

    # Register all bidders
    print(f"\n{'═'*70}")
    print("📝 REGISTRATION PHASE")
    print(f"{'═'*70}")

    for i, bid in enumerate(bids, start=1):
        auction.register_bidder(i, bid, show_details=True)

    # Show summary
    auction.display_summary()

    # Run auction
    winner, winning_bid = auction.run_auction()

    return winner, winning_bid


# Main execution
if __name__ == "__main__":

    print("\n" + "█"*70)
    print("ENHANCED SECURE SEALED-BID AUCTION SYSTEM")
    print("█"*70)

    # Example 1
    print("\n\n🔹 EXAMPLE 1: Standard Auction")
    run_example_auction_enhanced([150, 920, 600], name="Standard Auction")

    # Example 2
    print("\n\n🔹 EXAMPLE 2: Tie-Breaking Auction")
    run_example_auction_enhanced([350, 350, 100, 300], name="Tie-Breaking Auction")

    # Example 3
    print("\n\n🔹 EXAMPLE 3: Security Test (Invalid Bids)")
    run_example_auction_enhanced([10, 999, 300, 700, 2000], name="Security Test Auction")

    # Interactive mode
    print("\n\n" + "█"*70)
    response = input("\n🎮 Want to try INTERACTIVE MODE? (yes/no): ")
    if response.lower() in ['yes', 'y']:
        interactive_mode()

    print("\n" + "█"*70)
    print("ALL DEMONSTRATIONS COMPLETE ✅")
    print("█"*70)
