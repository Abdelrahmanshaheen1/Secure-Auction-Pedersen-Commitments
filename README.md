# Secure Sealed-Bid Auction (Secret Sharing + Commitments + MPC)

A team project (3 members) implementing a privacy-preserving sealed-bid auction using three cryptographic primitives together: additive secret sharing, Pedersen-style commitments with zero-knowledge range proofs, and secure multi-party comparison (MPC).

**Note:** this was a 3-person team project; the cryptographic design, protocol, and implementation below reflect joint work, not solo work.

## Design

- **Secret sharing (3-party):** each bid is split into 3 random shares distributed across 3 servers; no single server ever sees a full bid.
- **Commitments + ZK range proofs:** a bidder commits to their bid (`C = hash(bid + randomness)`) so it can't be changed later, and proves via a zero-knowledge range proof that the bid falls within an allowed range (e.g. 100–1000) *without revealing the bid itself*. Invalid bids are rejected before they're ever shared with the servers.
- **MPC comparison:** to find the winner, servers compute pairwise differences of their own bid shares, exchange *only the differences* (never the shares themselves), and reconstruct which bid was larger — without ever reconstructing either bid individually. Finding the maximum is done via repeated pairwise comparison across all bids; only the winning bid is ever reconstructed.

## Security properties

- Losing bids are never revealed, even to the servers.
- Compromising any single server reveals nothing about any bid (all 3 servers would need to collude to break secrecy).
- Bids can't be changed after commitment, and out-of-range bids are rejected before participating in the auction.

## Testing (as reported in the project documentation)

| Scenario | Input bids | Result |
|---|---|---|
| Normal auction, distinct bids | [150, 920, 600] | Winner: Bidder 2, bid 920 |
| Tie | [350, 350, 100, 300] | Winner: Bidder 1 (first bidder wins ties) |
| Invalid bids mixed in | [10, 999, 300, 700, 2000] | 10 and 2000 rejected (out of range); winner: Bidder 2, bid 999 |

## ✅ Verified

The notebook generates its own helper modules (`commitments.py`, `secret_sharing.py`, `zkproofs.py`, `mpc.py`, `auction.py`) via `%%writefile` cells, so it's self-contained. I ran `auction.py` directly and it reproduces exactly the results claimed above — the tie scenario and the invalid-bid-rejection scenario both matched the write-up precisely. (`auction_enhanced.py` adds an interactive CLI demo mode with `input()` prompts, which only hangs in a non-interactive run — not a bug, just not run automatically here.)

## Skills demonstrated

Applied cryptography beyond textbook definitions — combining secret sharing, commitment schemes, zero-knowledge proofs, and MPC into one coherent protocol — and clear protocol-level security reasoning (what each primitive defends against, and why all three are needed together).
