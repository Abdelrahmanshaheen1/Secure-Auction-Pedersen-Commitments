"""
zkproofs.py - Zero-knowledge range proof for a Pedersen commitment

Claim proved: the committed bid v satisfies  min_bid <= v <= max_bid,
without revealing v. No trusted setup, built only from the commitment scheme.

How it works
------------
1. To show x >= 0 and x < 2^n, write x in binary, x = sum(b_i * 2^i), and commit to each
   bit:  C_i = b_i*G + r_i*H, choosing the r_i so that  sum(2^i * C_i) = x*G + r*H,
   i.e. the weighted sum of the bit commitments *equals* the commitment to x.
   The verifier checks that equation. It is exactly what ties the bits to the bid.
2. For each C_i the prover shows it commits to 0 or 1, with a Fiat-Shamir "OR proof"
   (Cramer-Damgard-Schoenmakers): knowledge of r_i with C_i = r_i*H  OR  C_i - G = r_i*H.
   The branch that is not true is simulated, so the verifier cannot tell which one is real.
3. Do this twice: for x = bid - min (so bid >= min) and for x = max - bid (so bid <= max).
   Both are computed from the same commitment C, using
        C - min*G   commits to bid - min      and      max*G - C   commits to max - bid.

Everything is bound to the statement (commitment, range, bidder context) through the
Fiat-Shamir hash, so a proof cannot be replayed for another commitment or another bidder.
"""

import hashlib
import secrets

import ec

DOMAIN = b"secure-auction/range-proof/v1"


# ---------------------------------------------------------------------------------
# Fiat-Shamir challenge
# ---------------------------------------------------------------------------------
def _serialize(item):
    if isinstance(item, bytes):
        data = b"B" + item
    elif isinstance(item, str):
        data = b"S" + item.encode()
    elif isinstance(item, int):
        data = b"I" + item.to_bytes(max(1, (item.bit_length() + 7) // 8), "big")
    else:                                   # a curve point or None
        data = b"P" + ec.encode_point(item)
    return len(data).to_bytes(4, "big") + data    # length prefix: no ambiguity between fields


def _challenge(*items):
    digest = hashlib.sha256(DOMAIN + b"".join(_serialize(i) for i in items)).digest()
    return int.from_bytes(digest, "big") % ec.N


# ---------------------------------------------------------------------------------
# OR proof that a commitment holds a bit
# ---------------------------------------------------------------------------------
def _prove_bit(C, bit, r, params, binding):
    """
    Prove C = bit*G + r*H with bit in {0, 1}. The two statements are
        Y0 = C        = r*H   (bit = 0)
        Y1 = C - G    = r*H   (bit = 1)
    Returns (e0, e1, z0, z1).
    """
    G, H = params.G, params.H
    Y = [C, ec.point_sub(C, G)]
    fake = 1 - bit

    # Simulate the false branch: pick its challenge and response, solve for its commitment.
    e_fake = secrets.randbelow(ec.N)
    z_fake = secrets.randbelow(ec.N)
    A = [None, None]
    A[fake] = ec.point_sub(ec.scalar_mult(z_fake, H), ec.scalar_mult(e_fake, Y[fake]))

    # Honest branch: a normal Schnorr commitment.
    k = secrets.randbelow(ec.N)
    A[bit] = ec.scalar_mult(k, H)

    e_total = _challenge(binding, C, A[0], A[1])
    e_real = (e_total - e_fake) % ec.N          # the two challenges must add up to e_total
    z_real = (k + e_real * r) % ec.N

    e, z = [0, 0], [0, 0]
    e[bit], z[bit] = e_real, z_real
    e[fake], z[fake] = e_fake, z_fake
    return (e[0], e[1], z[0], z[1])


def _verify_bit(C, proof, params, binding):
    e0, e1, z0, z1 = proof
    if not all(isinstance(v, int) and 0 <= v < ec.N for v in (e0, e1, z0, z1)):
        return False
    G, H = params.G, params.H
    # Recompute each branch's commitment from (challenge, response), as the verifier must.
    A0 = ec.point_sub(ec.scalar_mult(z0, H), ec.scalar_mult(e0, C))
    A1 = ec.point_sub(ec.scalar_mult(z1, H), ec.scalar_mult(e1, ec.point_sub(C, G)))
    return (e0 + e1) % ec.N == _challenge(binding, C, A0, A1)


# ---------------------------------------------------------------------------------
# Proof that a committed value lies in [0, 2^n)
# ---------------------------------------------------------------------------------
def _bit_commitments(x, r_x, n, params):
    """Commit to the n bits of x so that sum(2^i * C_i) commits to x with randomness r_x."""
    bits = [(x >> i) & 1 for i in range(n)]
    rs = [secrets.randbelow(ec.N) for _ in range(n - 1)]
    partial = sum(rs[i] * (1 << i) for i in range(n - 1))
    rs.append((r_x - partial) * pow(1 << (n - 1), -1, ec.N) % ec.N)
    Cs = [ec.point_add(ec.scalar_mult(b, params.G), ec.scalar_mult(r, params.H))
          for b, r in zip(bits, rs)]
    return bits, rs, Cs


def _bit_binding(binding, index):
    return binding + _serialize(index)


def _prove_nonnegative(x, r_x, C_x, n, params, binding):
    bits, rs, Cs = _bit_commitments(x, r_x, n, params)
    proofs = [_prove_bit(C, b, r, params, _bit_binding(binding, i))
              for i, (C, b, r) in enumerate(zip(Cs, bits, rs))]
    part = {"bit_commitments": Cs, "bit_proofs": proofs}
    return part, bits, rs


def _verify_nonnegative(part, C_x, n, params, binding):
    Cs, proofs = part["bit_commitments"], part["bit_proofs"]
    if len(Cs) != n or len(proofs) != n:
        return False
    # The bits must add up to the committed value ...
    total = None
    for i, C in enumerate(Cs):
        total = ec.point_add(total, ec.scalar_mult(1 << i, C))
    if total != C_x:
        return False
    # ... and each one must really be a bit.
    return all(_verify_bit(C, p, params, _bit_binding(binding, i))
               for i, (C, p) in enumerate(zip(Cs, proofs)))


# ---------------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------------
def range_bits(min_bid, max_bid):
    """Number of bits needed for the width of the range."""
    return (max_bid - min_bid).bit_length()


def _binding(commitment, min_bid, max_bid, context, side):
    """Everything the proof is about, as bytes that get hashed into every challenge."""
    return b"".join(_serialize(item) for item in
                    (commitment, min_bid, max_bid, context, side))


def generate_range_proof_with_witness(bid, randomness, min_bid, max_bid, params, context=b""):
    """
    Returns (proof, witness). The proof is public. The witness (the bits of bid - min and
    the randomness behind their commitments) stays with the bidder, who secret-shares it
    with the servers (see auction.py).
    """
    if not 0 <= min_bid < max_bid:
        raise ValueError("need 0 <= min_bid < max_bid")
    if bid < min_bid or bid > max_bid:
        raise ValueError(f"Bid {bid} is not in range [{min_bid}, {max_bid}]")

    n = range_bits(min_bid, max_bid)
    C = ec.point_add(ec.scalar_mult(bid, params.G), ec.scalar_mult(randomness, params.H))

    C_low = ec.point_sub(C, ec.scalar_mult(min_bid, params.G))       # commits to bid - min
    C_high = ec.point_sub(ec.scalar_mult(max_bid, params.G), C)      # commits to max - bid

    low, low_bits, low_rs = _prove_nonnegative(
        bid - min_bid, randomness, C_low, n, params, _binding(C, min_bid, max_bid, context, "low"))
    high, _, _ = _prove_nonnegative(
        max_bid - bid, -randomness % ec.N, C_high, n, params,
        _binding(C, min_bid, max_bid, context, "high"))

    proof = {"min_bid": min_bid, "max_bid": max_bid, "n_bits": n, "low": low, "high": high}
    witness = {"bits": low_bits, "randomness": low_rs}
    return proof, witness


def generate_range_proof(bid, randomness, min_bid, max_bid, params, context=b""):
    """Prove min_bid <= bid <= max_bid for the commitment to `bid` with `randomness`."""
    proof, _ = generate_range_proof_with_witness(bid, randomness, min_bid, max_bid, params, context)
    return proof


def verify_range_proof(proof, commitment, params, min_bid, max_bid, context=b""):
    """
    Check that `commitment` hides a value in [min_bid, max_bid]. The range to enforce is
    passed in by the verifier: never trust the range stated inside the proof, or a bidder
    could "prove" membership in a range of their own choosing.

    Returns False for any invalid or malformed proof; it never raises on
    attacker-supplied input.
    """
    try:
        if not (0 <= min_bid < max_bid):
            return False
        n = range_bits(min_bid, max_bid)
        if (proof["min_bid"], proof["max_bid"], proof["n_bits"]) != (min_bid, max_bid, n):
            return False
        if commitment is None or not ec.is_on_curve(commitment):
            return False

        C_low = ec.point_sub(commitment, ec.scalar_mult(min_bid, params.G))
        C_high = ec.point_sub(ec.scalar_mult(max_bid, params.G), commitment)
        return (
            _verify_nonnegative(proof["low"], C_low, n, params,
                                _binding(commitment, min_bid, max_bid, context, "low"))
            and _verify_nonnegative(proof["high"], C_high, n, params,
                                    _binding(commitment, min_bid, max_bid, context, "high"))
        )
    except (KeyError, TypeError, ValueError, AttributeError, IndexError, OverflowError):
        return False


def create_and_verify_proof(bid, randomness, min_bid, max_bid, params):
    """Helper: commit, prove, verify. Returns (commitment, proof, is_valid)."""
    from commitments import commit_bid

    commitment = commit_bid(bid, randomness, params)
    try:
        proof = generate_range_proof(bid, randomness, min_bid, max_bid, params)
        return commitment, proof, verify_range_proof(proof, commitment, params, min_bid, max_bid)
    except ValueError:
        return commitment, None, False
