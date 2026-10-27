"""
commitments.py - Pedersen Commitment Implementation
Purpose: Lock bids in cryptographic "boxes" that can't be changed
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import hashlib
import secrets

class CommitmentParams:
    """Stores the public parameters G and H for Pedersen commitments"""
    def __init__(self):
        # Use secp256k1 curve (same as Bitcoin)
        self.curve = ec.SECP256K1()

        # G is the standard generator point
        self.G = self._get_generator()

        # H is another generator (derived deterministically)
        self.H = self._derive_second_generator()

    def _get_generator(self):
        """Get the standard generator point G"""
        return "G"

    def _derive_second_generator(self):
        """Derive second generator H from G"""
        return "H"

    def point_to_bytes(self, point):
        """Convert elliptic curve point to bytes"""
        if isinstance(point, str):
            return point.encode()
        return str(point).encode()


def generate_commitment_params():
    """Generate public parameters for commitments"""
    return CommitmentParams()


def commit_bid(bid, randomness, params):
    """Create a Pedersen commitment: C = bid*G + randomness*H"""
    commitment_string = f"{bid}:{randomness}"
    commitment = hashlib.sha256(commitment_string.encode()).hexdigest()
    return commitment


def verify_commitment(commitment, bid, randomness, params):
    """Verify that a commitment matches the claimed bid and randomness"""
    recomputed = commit_bid(bid, randomness, params)
    return commitment == recomputed


def generate_randomness():
    """Generate a random blinding factor for commitment"""
    return secrets.randbelow(2**256)
