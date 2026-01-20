"""
Zero Knowledge Proof - Digital Forensics Verifier Module
=========================================================
Implements the Verifier side for file integrity verification.

VERIFIER'S ROLE IN FORENSICS:
-----------------------------
The verifier confirms that the prover possesses a specific file
(identified by its public value) without:
- Seeing the file content
- Knowing the file hash
- Having access to the original file

USE CASES:
----------
1. Court evidence verification
   - Lawyer proves they have unmodified evidence
   - Court verifies without receiving the evidence file

2. Chain of custody
   - Each handler proves file was not modified
   - No need to transfer actual files

3. Secure backup verification
   - Prove backup integrity without downloading

4. Distributed forensics
   - Multiple parties verify same evidence
   - Evidence file stays with original custodian

VERIFICATION PROCESS:
---------------------
1. Verifier has registered public value y (from original file)
2. Prover claims to have a file with same hash
3. ZKP protocol proves claim without revealing hash
4. If verified, prover definitely has the correct file
"""

import secrets


class ForensicsVerifier:
    """
    Verifier class for ZKP-based file integrity verification.
    Validates file possession proofs without accessing file content.
    """
    
    # Must match prover parameters exactly
    PRIME = int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16
    )
    GENERATOR = 2
    
    def __init__(self):
        """
        Initialize the forensics verifier.
        Public value is registered during evidence submission phase.
        """
        self.registered_public_value = None
        self.challenge = None
        self.evidence_id = None
    
    def register_evidence(self, public_value, evidence_id=None):
        """
        Register evidence for future verification.
        
        Parameters:
            public_value: Integer y = g^x mod p (from prover)
            evidence_id: Optional string identifier for the evidence
        
        FORENSICS CONTEXT:
        This simulates the initial evidence submission where:
        - Original file holder computes public value
        - Public value is recorded in evidence log
        - Original file stays with custodian
        - Only public value is stored centrally
        
        SECURITY:
        Public value reveals nothing about file content.
        Computing the file hash from y is computationally infeasible.
        """
        self.registered_public_value = public_value
        self.evidence_id = evidence_id if evidence_id else "EVIDENCE_001"
    
    def generate_challenge(self):
        """
        Generate random challenge for the prover.
        
        PROTOCOL STEP 2:
        Generate cryptographically random c from [1, PRIME-2]
        
        Returns:
            Integer c (challenge value)
        
        SECURITY REQUIREMENTS:
        Challenge must be:
        1. Generated AFTER receiving commitment
        2. Unpredictable to the prover
        3. Fresh for each verification attempt
        """
        self.challenge = secrets.randbelow(self.PRIME - 2) + 1
        return self.challenge
    
    def verify_proof(self, commitment, response, public_value=None):
        """
        Verify a file integrity proof.
        
        PROTOCOL STEP 4 - VERIFICATION:
        Check if g^s == t * y^c (mod p)
        
        Parameters:
            commitment: Integer t from prover
            response: Integer s from prover
            public_value: Optional y (uses registered if not provided)
        
        Returns:
            Boolean - True if file integrity is confirmed
        
        VERIFICATION MEANING:
        - True: Prover has file with EXACT same content as original
        - False: Prover's file is different (modified, corrupted, or fake)
        
        FORENSICS IMPLICATION:
        A verified proof means:
        - File has not been tampered with
        - File is identical to originally registered file
        - Chain of custody is maintained
        """
        # Use provided or registered public value
        y = public_value if public_value is not None else self.registered_public_value
        
        if y is None:
            raise ValueError("No evidence registered. Call register_evidence() first.")
        
        if self.challenge is None:
            raise ValueError("No challenge generated. Call generate_challenge() first.")
        
        # Compute left side: g^s mod p
        left_side = pow(self.GENERATOR, response, self.PRIME)
        
        # Compute right side: t * y^c mod p
        y_power_c = pow(y, self.challenge, self.PRIME)
        right_side = (commitment * y_power_c) % self.PRIME
        
        # Verification result
        is_valid = (left_side == right_side)
        
        return is_valid
    
    def verify_complete_proof(self, proof_dict):
        """
        Verify a complete proof dictionary.
        
        Parameters:
            proof_dict: Dictionary with commitment, response, public_value
        
        Returns:
            Boolean - True if verified
        """
        return self.verify_proof(
            commitment=proof_dict["commitment"],
            response=proof_dict["response"],
            public_value=proof_dict.get("public_value", self.registered_public_value)
        )
    
    def get_verification_status(self, is_valid):
        """
        Get human-readable verification status.
        
        Parameters:
            is_valid: Boolean from verify_proof()
        
        Returns:
            String status with forensics context
        """
        if is_valid:
            return "INTEGRITY VERIFIED"
        else:
            return "INTEGRITY FAILED"
    
    def get_detailed_status(self, is_valid):
        """
        Get detailed verification status for forensics report.
        
        Parameters:
            is_valid: Boolean from verify_proof()
        
        Returns:
            dict with detailed status information
        """
        if is_valid:
            return {
                "status": "VERIFIED",
                "integrity": "CONFIRMED",
                "evidence_id": self.evidence_id,
                "conclusion": "File matches original evidence. Chain of custody intact.",
                "recommendation": "Evidence is admissible."
            }
        else:
            return {
                "status": "FAILED",
                "integrity": "COMPROMISED",
                "evidence_id": self.evidence_id,
                "conclusion": "File does NOT match original evidence. Possible tampering.",
                "recommendation": "Evidence integrity cannot be confirmed."
            }
    
    def reset(self):
        """
        Reset verifier state for new verification session.
        """
        self.challenge = None
    
    def clear_registration(self):
        """
        Clear registered evidence.
        Use when switching to different evidence.
        """
        self.registered_public_value = None
        self.challenge = None
        self.evidence_id = None
    
    @staticmethod
    def get_prime():
        """Return the prime modulus."""
        return ForensicsVerifier.PRIME
    
    @staticmethod
    def get_generator():
        """Return the generator."""
        return ForensicsVerifier.GENERATOR