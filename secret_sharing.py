"""
secret_sharing.py - Additive secret sharing

A value v is split into shares that add up to v modulo a prime. Any proper subset of the
shares is uniformly random and says nothing about v.

The modulus is the order of the secp256k1 group (a 256-bit prime) so that shares of a
bid's bits line up with the Pedersen commitments to those bits (see auction.py).
"""

import secrets

import ec


def get_large_prime():
    """The modulus for all shares: the (prime) order of the secp256k1 group."""
    return ec.N


def share_value(value, p=None, num_shares=3):
    """Split a value into additive shares modulo p."""
    p = ec.N if p is None else p
    shares = [secrets.randbelow(p) for _ in range(num_shares - 1)]
    shares.append((value - sum(shares)) % p)
    return shares


def reconstruct(shares, p=None):
    """Recombine shares into the original value."""
    p = ec.N if p is None else p
    return sum(shares) % p
