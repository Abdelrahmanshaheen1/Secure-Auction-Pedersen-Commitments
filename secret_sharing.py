"""
secret_sharing.py - Additive Secret Sharing
"""

import secrets


def share_value(value, p, num_shares=3):
    """Split a value into additive shares modulo p"""

    shares = []
    for i in range(num_shares - 1):
        random_share = secrets.randbelow(p)
        shares.append(random_share)

    sum_of_shares = sum(shares) % p
    last_share = (value - sum_of_shares) % p
    shares.append(last_share)

    return shares


def reconstruct(shares, p):
    """Reconstruct the original value from shares"""
    total = sum(shares) % p
    return total


def get_large_prime():
    """Return a large prime number for modular arithmetic"""
    return 2305843009213693951
