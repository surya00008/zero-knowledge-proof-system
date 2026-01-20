"""
Zero Knowledge Proof - Authentication Prover Module
====================================================
Implements the Prover side of a Schnorr-like ZKP protocol.

CRYPTOGRAPHIC PROTOCOL EXPLANATION:
-----------------------------------
This implements an interactive ZKP where:
1. Prover knows a secret (password)
2. Prover convinces Verifier they know the secret
3. Secret is NEVER transmitted or revealed

MATHEMATICAL BASIS:
-------------------
We use modular arithmetic in a prime field.
- p = large prime number (defines the field)
- g = generator (base for exponentiation)
- x = secret (derived from password hash)
- y = g^x mod p (public commitment, safe to share)

PROTOCOL STEPS:
---------------
1. COMMITMENT: Prover picks random r, sends t = g^r mod p
2. CHALLENGE: Verifier sends random challenge c
3. RESPONSE: Prover computes s = (r + c * x) mod (p-1)
4. VERIFY: Verifier checks if g^s == t * y^c mod p

ZERO KNOWLEDGE PROPERTY:
------------------------
- Verifier learns nothing about x (the secret)
- Only proof values (t, s) are exchanged
- Even if intercepted, secret cannot be recovered
"""

import hashlib
import secrets


class AuthenticationProver:
    """
    Prover class for ZKP-based authentication.
    Generates proofs that demonstrate knowledge of password without revealing it.
    """
    
    # Cryptographic parameters
    # Using a 2048-bit safe prime for security
    # In production, use standardized primes (RFC 3526)
    # For this demo, we use a smaller prime for clarity
    
    # 256-bit prime (sufficient for demonstration)
    PRIME = int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16
    )
    
    # Generator (primitive root modulo PRIME)
    GENERATOR = 2
    
    def __init__(self):
        """
        Initialize the prover.
        Secret is set later via set_secret() method.
        """
        self.secret = None
        self.random_nonce = None
        self.commitment = None
        self.public_value = None
    
    def _hash_to_integer(self, data):
        """
        Convert arbitrary data to an integer in the valid range.
        Uses SHA-256 and reduces modulo (PRIME - 1).
        
        Parameters:
            data: bytes or string to hash
        
        Returns:
            Integer in range [1, PRIME-2]
        
        CRYPTOGRAPHIC NOTE:
        We use (PRIME - 1) as modulus because exponents work in
        the multiplicative group of order (p-1).
        Adding 1 ensures result is never zero.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        hash_bytes = hashlib.sha256(data).digest()
        hash_int = int.from_bytes(hash_bytes, byteorder='big')
        
        # Reduce to valid range [1, PRIME-2]
        result = (hash_int % (self.PRIME - 2)) + 1
        return result
    
    def set_secret(self, password):
        """
        Set the secret from a password.
        Password is hashed and converted to integer.
        Original password is NOT stored.
        
        Parameters:
            password: The secret password string
        
        SECURITY NOTE:
        The password itself is never stored.
        Only the derived integer is kept in memory.
        """
        # Convert password to secret integer
        self.secret = self._hash_to_integer(password)
        
        # Compute public value: y = g^x mod p
        # This is safe to share - computing x from y is the
        # Discrete Logarithm Problem (computationally hard)
        self.public_value = pow(
            self.GENERATOR,
            self.secret,
            self.PRIME
        )
    
    def get_public_value(self):
        """
        Get the public value y = g^x mod p.
        This is shared with the verifier during registration.
        
        Returns:
            Integer representing the public commitment
        """
        if self.public_value is None:
            raise ValueError("Secret not set. Call set_secret() first.")
        return self.public_value
    
    def generate_commitment(self):
        """
        Generate the first message of the ZKP protocol.
        
        PROTOCOL STEP 1 - COMMITMENT:
        - Pick random nonce r from [1, PRIME-2]
        - Compute commitment t = g^r mod p
        - Store r privately, send t to verifier
        
        Returns:
            Integer t (the commitment)
        
        SECURITY NOTE:
        The random nonce r must be cryptographically secure.
        We use secrets.randbelow() which is secure for crypto use.
        Nonce r is never transmitted - only t is sent.
        """
        # Generate secure random nonce
        # Range is [1, PRIME-2] to ensure valid exponent
        self.random_nonce = secrets.randbelow(self.PRIME - 2) + 1
        
        # Compute commitment: t = g^r mod p
        self.commitment = pow(
            self.GENERATOR,
            self.random_nonce,
            self.PRIME
        )
        
        return self.commitment
    
    def generate_response(self, challenge):
        """
        Generate the response to verifier's challenge.
        
        PROTOCOL STEP 3 - RESPONSE:
        Given challenge c from verifier, compute:
        s = (r + c * x) mod (p - 1)
        
        Parameters:
            challenge: Integer c from verifier
        
        Returns:
            Integer s (the response)
        
        MATHEMATICAL EXPLANATION:
        The response s encodes both the random nonce r and
        the secret x, but in a way that:
        - Without knowing r, you cannot extract x
        - Without knowing x, you cannot forge a valid s
        
        ZERO KNOWLEDGE PROPERTY:
        The value s alone reveals nothing about x because
        r is random and unknown to the verifier.
        """
        if self.secret is None:
            raise ValueError("Secret not set. Call set_secret() first.")
        if self.random_nonce is None:
            raise ValueError("Commitment not generated. Call generate_commitment() first.")
        
        # Compute response: s = (r + c * x) mod (p - 1)
        # We use (p - 1) because exponents are in Z_{p-1}
        response = (
            self.random_nonce + challenge * self.secret
        ) % (self.PRIME - 1)
        
        return response
    
    def create_proof(self, challenge):
        """
        Create a complete proof tuple for the given challenge.
        
        Parameters:
            challenge: Integer c from verifier
        
        Returns:
            dict containing commitment and response
        """
        commitment = self.generate_commitment()
        response = self.generate_response(challenge)
        
        return {
            "commitment": commitment,
            "response": response,
            "public_value": self.public_value
        }
    
    def clear_secret(self):
        """
        Securely clear the secret from memory.
        Should be called after authentication is complete.
        
        SECURITY NOTE:
        This helps minimize the time secret exists in memory.
        In Python, true secure deletion is complex due to
        garbage collection, but this is best effort.
        """
        self.secret = None
        self.random_nonce = None
        self.commitment = None
    
    @staticmethod
    def get_prime():
        """Return the prime modulus used in the protocol."""
        return AuthenticationProver.PRIME
    
    @staticmethod
    def get_generator():
        """Return the generator used in the protocol."""
        return AuthenticationProver.GENERATOR