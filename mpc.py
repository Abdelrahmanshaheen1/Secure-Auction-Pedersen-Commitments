"""
mpc.py - Multi-Party Computation Operations
"""


def mpc_add(shares_a, shares_b, p):
    """Add two secret-shared values"""
    shares_sum = [(shares_a[i] + shares_b[i]) % p for i in range(len(shares_a))]
    return shares_sum


def mpc_sub(shares_a, shares_b, p):
    """Subtract two secret-shared values"""
    shares_diff = [(shares_a[i] - shares_b[i]) % p for i in range(len(shares_a))]
    return shares_diff


def mpc_mult(shares_a, shares_b, p):
    """Multiply two secret-shared values (simplified)"""
    from secret_sharing import reconstruct, share_value

    a = reconstruct(shares_a, p)
    b = reconstruct(shares_b, p)
    product = (a * b) % p

    return share_value(product, p)


def mpc_compare(shares_a, shares_b, p):
    """Compare two secret-shared values: is a > b?"""
    from secret_sharing import reconstruct

    shares_diff = mpc_sub(shares_a, shares_b, p)
    diff = reconstruct(shares_diff, p)

    if diff == 0:
        return 0
    elif diff < p // 2:
        return 1
    else:
        return -1


def mpc_argmax(all_shares, p):
    """Find the index of maximum value among secret-shared values"""
    from secret_sharing import reconstruct

    if not all_shares:
        return None, None

    max_index = 0
    max_shares = all_shares[0]

    for i in range(1, len(all_shares)):
        current_shares = all_shares[i]
        comparison = mpc_compare(current_shares, max_shares, p)

        if comparison > 0:
            max_index = i
            max_shares = current_shares

    max_value = reconstruct(max_shares, p)
    return max_index, max_value
