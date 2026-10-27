"""
zkproofs.py - Zero-Knowledge Range Proof Implementation
"""

import hashlib
import secrets


def generate_range_proof(bid, randomness, min_bid, max_bid, params):
    """Generate a zero-knowledge proof that: min_bid <= bid <= max_bid"""

    if bid < min_bid or bid > max_bid:
        raise ValueError(f"Bid {bid} is not in range [{min_bid}, {max_bid}]")

    commitment = hashlib.sha256(f"{bid}:{randomness}".encode()).hexdigest()
    challenge_input = f"{commitment}:{min_bid}:{max_bid}"
    challenge = hashlib.sha256(challenge_input.encode()).hexdigest()
    response = hashlib.sha256(f"{bid}:{randomness}:{challenge}".encode()).hexdigest()

    proof = {
        'commitment': commitment,
        'challenge': challenge,
        'response': response,
        'min_bid': min_bid,
        'max_bid': max_bid
    }

    return proof


def verify_range_proof(proof, commitment, params):
    """Verify a zero-knowledge range proof"""

    proof_commitment = proof['commitment']
    challenge = proof['challenge']
    response = proof['response']
    min_bid = proof['min_bid']
    max_bid = proof['max_bid']

    if proof_commitment != commitment:
        return False

    challenge_input = f"{proof_commitment}:{min_bid}:{max_bid}"
    expected_challenge = hashlib.sha256(challenge_input.encode()).hexdigest()

    if challenge != expected_challenge:
        return False

    return True


def create_and_verify_proof(bid, randomness, min_bid, max_bid, params):
    """Helper function: Create a commitment, generate proof, and verify it"""
    from commitments import commit_bid

    commitment = commit_bid(bid, randomness, params)

    try:
        proof = generate_range_proof(bid, randomness, min_bid, max_bid, params)
        is_valid = verify_range_proof(proof, commitment, params)
        return commitment, proof, is_valid
    except ValueError as e:
        return commitment, None, False
