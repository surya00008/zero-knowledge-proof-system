"""
Zero Knowledge Proof - Authentication Verifier Module
======================================================
Implements the Verifier side of a Schnorr-like ZKP protocol.

VERIFIER'S ROLE:
----------------
1. Generate random challenge
2. Receive commitment and response from prover
3. Verify the mathematical relationship
4. Accept or reject the proof

VERIFICATION EQUATION:
----------------------
The verifier checks: g^s == t * y^c (mod p)

Where:
- g = generator
- s = prover's response
- t = prover's commitment
- y = prover's public value (g^x mod p)
- c = verifier's challenge
- p = prime modulus

WHY THIS WORKS:
---------------
If prover knows x (the secret):
    s = r + c*x (mod p-1)
    g^s = g^(r + c*x) = g^r * g^(c*x) = g^r * (g^x)^c = t * y^c (mod p)

If prover does NOT know x:
    They cannot compute valid s without knowing x
    Probability of guessing correctly is negligible (1/p)

ZERO KNOWLEDGE GUARANTEE:
-------------------------
Verifier only sees: t, c, s, y
Verifier cannot compute x because:
- Discrete log problem: cannot get x from y = g^x
- Random nonce r masks x in the response s
"""

import secrets


class AuthenticationVerifier:
    """
    Verifier class for ZKP-based authentication.
    Validates proofs without learning the secret.
    """
    
    # Must use same parameters as Prover
    PRIME = int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16
    )
    GENERATOR = 2
    
    def __init__(self):
        """
        Initialize the verifier.
        Stores the registered public value for verification.
        """
        self.registered_public_value = None
        self.challenge = None
    
    def register_public_value(self, public_value):
        """
        Register a user's public value during enrollment.
        This simulates the registration phase where prover
        shares their public value y = g^x mod p.
        
        Parameters:
            public_value: Integer y from prover
        
        SECURITY NOTE:
        Only the public value is stored, never the secret.
        This is safe because computing x from y is hard
        (Discrete Logarithm Problem).
        """
        self.registered_public_value = public_value
    
    def generate_challenge(self):
        """
        Generate a random challenge for the prover.
        
        PROTOCOL STEP 2 - CHALLENGE:
        Generate random c from [1, PRIME-2]
        
        Returns:
            Integer c (the challenge)
        
        SECURITY NOTE:
        Challenge must be:
        1. Unpredictable (cryptographically random)
        2. Generated AFTER receiving commitment
        3. Fresh for each authentication attempt
        
        If prover could predict the challenge, they could
        forge proofs without knowing the secret.
        """
        # Generate cryptographically secure random challenge
        self.challenge = secrets.randbelow(self.PRIME - 2) + 1
        return self.challenge
    
    def verify_proof(self, commitment, response, public_value=None):
        """
        Verify a ZKP proof from the prover.
        
        PROTOCOL STEP 4 - VERIFICATION:
        Check if g^s == t * y^c (mod p)
        
        Parameters:
            commitment: Integer t from prover
            response: Integer s from prover
            public_value: Integer y (optional, uses registered if not provided)
        
        Returns:
            Boolean - True if proof is valid, False otherwise
        
        VERIFICATION MATHEMATICS:
        Left side:  g^s mod p
        Right side: (t * y^c) mod p
        
        If left == right, prover knows the secret.
        """
        # Use provided public value or fall back to registered one
        y = public_value if public_value is not None else self.registered_public_value
        
        if y is None:
            raise ValueError("No public value available. Register first.")
        
        if self.challenge is None:
            raise ValueError("No challenge generated. Call generate_challenge() first.")
        
        # Compute left side: g^s mod p
        left_side = pow(self.GENERATOR, response, self.PRIME)
        
        # Compute right side: t * y^c mod p
        # First compute y^c mod p
        y_power_c = pow(y, self.challenge, self.PRIME)
        
        # Then multiply by t and take mod p
        right_side = (commitment * y_power_c) % self.PRIME
        
        # Proof is valid if both sides are equal
        is_valid = (left_side == right_side)
        
        return is_valid
    
    def verify_complete_proof(self, proof_dict):
        """
        Verify a complete proof dictionary.
        
        Parameters:
            proof_dict: Dictionary with commitment, response, public_value
        
        Returns:
            Boolean - True if proof is valid
        """
        return self.verify_proof(
            commitment=proof_dict["commitment"],
            response=proof_dict["response"],
            public_value=proof_dict.get("public_value", self.registered_public_value)
        )
    
    def full_verification(self, commitment, response, public_value=None):
        """
        Perform full verification with fresh challenge.
        This is used when challenge was already sent to prover.
        
        Parameters:
            commitment: Integer t from prover
            response: Integer s from prover  
            public_value: Integer y (optional)
        
        Returns:
            tuple: (is_valid, challenge_used)
        """
        is_valid = self.verify_proof(commitment, response, public_value)
        return is_valid, self.challenge
    
    def reset(self):
        """
        Reset verifier state for new authentication session.
        Challenge is cleared to ensure fresh challenge each time.
        """
        self.challenge = None
    
    def get_verification_status(self, is_valid):
        """
        Get human-readable verification status.
        
        Parameters:
            is_valid: Boolean result from verify_proof()
        
        Returns:
            String status message
        """
        if is_valid:
            return "VERIFIED"
        else:
            return "REJECTED"
    
    @staticmethod
    def get_prime():
        """Return the prime modulus used in the protocol."""
        return AuthenticationVerifier.PRIME
    
    @staticmethod
    def get_generator():
        """Return the generator used in the protocol."""
        return AuthenticationVerifier.GENERATOR