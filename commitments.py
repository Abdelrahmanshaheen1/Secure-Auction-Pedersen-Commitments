"""
commitments.py - Pedersen commitments on secp256k1

    C = bid*G + randomness*H

* Hiding:  C reveals nothing about the bid, because randomness is uniform and
           randomness*H is uniform over the group (information-theoretic).
* Binding: opening C to two different bids would reveal log_G(H). H is derived by
           hashing a public seed, so nobody knows that value, and finding it means
           solving the discrete-log problem.
* Homomorphic: C(a, r1) + C(b, r2) == C(a + b, r1 + r2). The range proof relies on this.
"""

import secrets

import ec


class CommitmentParams:
    """Public parameters: the two generators G and H and the group order."""

    SEED_H = b"secure-auction/pedersen/H/v1"

    def __init__(self):
        self.curve = "secp256k1"
        self.order = ec.N
        self.G = ec.G
        # "Nothing up my sleeve": H comes from hashing a public string, so no one
        # knows an x with H = x*G. If someone did, they could open commitments to any bid.
        self.H = ec.hash_to_point(self.SEED_H)

    def point_to_bytes(self, point):
        return ec.encode_point(point)


def generate_commitment_params():
    """Generate (deterministically derive) the public parameters for commitments."""
    return CommitmentParams()


def commit_bid(bid, randomness, params):
    """Create the Pedersen commitment C = bid*G + randomness*H (a curve point)."""
    return ec.point_add(
        ec.scalar_mult(bid, params.G),
        ec.scalar_mult(randomness, params.H),
    )


def verify_commitment(commitment, bid, randomness, params):
    """Check that a commitment opens to the claimed bid and randomness."""
    return commit_bid(bid, randomness, params) == commitment


def commitment_to_hex(commitment):
    """Short printable form of a commitment."""
    return ec.encode_point(commitment).hex()


def generate_randomness():
    """A uniformly random blinding factor in [0, group order)."""
    return secrets.randbelow(ec.N)
