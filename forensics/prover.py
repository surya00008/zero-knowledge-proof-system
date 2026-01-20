"""
Zero Knowledge Proof - Digital Forensics Prover Module
=======================================================
Implements the Prover side for file integrity verification.

USE CASE: DIGITAL FORENSICS
----------------------------
In digital forensics, investigators need to prove they possess
an authentic copy of evidence (file) without revealing the file
contents. This is important for:
- Chain of custody verification
- Evidence integrity in court
- Secure file verification across parties

CRYPTOGRAPHIC PROTOCOL:
-----------------------
Same Schnorr-like protocol as authentication, but:
- Secret x is derived from file hash (SHA-256)
- File content is never transmitted
- File hash is never exposed
- Only proof values are exchanged

PROTOCOL STEPS:
---------------
1. Prover computes file hash using SHA-256
2. Hash is converted to secret integer x
3. Public value y = g^x mod p is computed
4. Standard ZKP protocol proceeds:
   - Commitment: t = g^r mod p
   - Challenge: c (from verifier)
   - Response: s = r + c*x mod (p-1)
5. Verifier checks: g^s == t * y^c mod p

FILE SECURITY:
--------------
- File is read once to compute hash
- Hash exists only in memory as integer
- Original file content is never exposed
- Even the hash value is not transmitted
"""

import hashlib
import secrets
import os


class ForensicsProver:
    """
    Prover class for ZKP-based file integrity verification.
    Proves possession of a file without revealing its contents.
    """
    
    # Same cryptographic parameters as authentication
    # Must match verifier parameters exactly
    PRIME = int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16
    )
    GENERATOR = 2
    
    # Buffer size for reading large files (64 KB chunks)
    BUFFER_SIZE = 65536
    
    def __init__(self):
        """
        Initialize the forensics prover.
        File hash will be set via load_file() method.
        """
        self.secret = None
        self.random_nonce = None
        self.commitment = None
        self.public_value = None
        self.file_size = None
        self.file_name = None
    
    def _compute_file_hash(self, file_path):
        """
        Compute SHA-256 hash of a file.
        Uses chunked reading to handle large files efficiently.
        
        Parameters:
            file_path: Path to the file
        
        Returns:
            bytes: SHA-256 hash digest
        
        SECURITY NOTE:
        File is read in chunks to:
        1. Handle files of any size
        2. Minimize memory usage
        3. File content is processed but never stored
        """
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as file:
            # Read file in chunks
            while True:
                data = file.read(self.BUFFER_SIZE)
                if not data:
                    break
                sha256_hash.update(data)
        
        return sha256_hash.digest()
    
    def _compute_bytes_hash(self, file_bytes):
        """
        Compute SHA-256 hash of raw bytes.
        Used when file content is provided directly (e.g., from UI upload).
        
        Parameters:
            file_bytes: Raw bytes of file content
        
        Returns:
            bytes: SHA-256 hash digest
        """
        return hashlib.sha256(file_bytes).digest()
    
    def _hash_to_integer(self, hash_bytes):
        """
        Convert hash bytes to an integer in valid range.
        
        Parameters:
            hash_bytes: SHA-256 hash as bytes
        
        Returns:
            Integer in range [1, PRIME-2]
        
        CRYPTOGRAPHIC NOTE:
        We ensure the result is never zero by adding 1.
        Modulo (PRIME-2) ensures valid exponent range.
        """
        hash_int = int.from_bytes(hash_bytes, byteorder='big')
        result = (hash_int % (self.PRIME - 2)) + 1
        return result
    
    def load_file(self, file_path):
        """
        Load a file and compute its secret representation.
        
        Parameters:
            file_path: Path to the file to prove
        
        Returns:
            Boolean indicating success
        
        PROCESS:
        1. Verify file exists
        2. Compute SHA-256 hash of file
        3. Convert hash to secret integer
        4. Compute public value y = g^x mod p
        5. Store file metadata (name, size) for display
        
        SECURITY:
        - File content is never stored
        - Hash is converted to integer immediately
        - Only the derived secret exists in memory
        """
        # Verify file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Store file metadata (safe to display)
        self.file_name = os.path.basename(file_path)
        self.file_size = os.path.getsize(file_path)
        
        # Compute file hash
        file_hash = self._compute_file_hash(file_path)
        
        # Convert hash to secret integer
        self.secret = self._hash_to_integer(file_hash)
        
        # Compute public value: y = g^x mod p
        self.public_value = pow(
            self.GENERATOR,
            self.secret,
            self.PRIME
        )
        
        return True
    
    def load_file_bytes(self, file_bytes, file_name="uploaded_file"):
        """
        Load file from raw bytes (for UI file upload).
        
        Parameters:
            file_bytes: Raw bytes of file content
            file_name: Name of the file (for display)
        
        Returns:
            Boolean indicating success
        """
        # Store file metadata
        self.file_name = file_name
        self.file_size = len(file_bytes)
        
        # Compute hash of bytes
        file_hash = self._compute_bytes_hash(file_bytes)
        
        # Convert hash to secret integer
        self.secret = self._hash_to_integer(file_hash)
        
        # Compute public value
        self.public_value = pow(
            self.GENERATOR,
            self.secret,
            self.PRIME
        )
        
        return True
    
    def get_public_value(self):
        """
        Get the public value for verification.
        
        Returns:
            Integer y = g^x mod p
        """
        if self.public_value is None:
            raise ValueError("File not loaded. Call load_file() first.")
        return self.public_value
    
    def get_file_metadata(self):
        """
        Get safe-to-display file metadata.
        
        Returns:
            dict with file name and size
        
        NOTE: This does NOT include file content or hash.
        """
        return {
            "file_name": self.file_name,
            "file_size": self.file_size,
            "file_size_formatted": self._format_size(self.file_size)
        }
    
    def _format_size(self, size_bytes):
        """
        Format file size in human-readable format.
        
        Parameters:
            size_bytes: Size in bytes
        
        Returns:
            Formatted string (e.g., "1.5 MB")
        """
        if size_bytes is None:
            return "Unknown"
        
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        
        return f"{size_bytes:.2f} TB"
    
    def generate_commitment(self):
        """
        Generate commitment for ZKP protocol.
        
        PROTOCOL STEP 1:
        - Pick random nonce r
        - Compute t = g^r mod p
        - Return t (commitment)
        
        Returns:
            Integer t (commitment value)
        """
        # Generate secure random nonce
        self.random_nonce = secrets.randbelow(self.PRIME - 2) + 1
        
        # Compute commitment
        self.commitment = pow(
            self.GENERATOR,
            self.random_nonce,
            self.PRIME
        )
        
        return self.commitment
    
    def generate_response(self, challenge):
        """
        Generate response to verifier's challenge.
        
        PROTOCOL STEP 3:
        - Receive challenge c from verifier
        - Compute s = r + c*x mod (p-1)
        - Return s (response)
        
        Parameters:
            challenge: Integer c from verifier
        
        Returns:
            Integer s (response value)
        """
        if self.secret is None:
            raise ValueError("File not loaded. Call load_file() first.")
        if self.random_nonce is None:
            raise ValueError("Commitment not generated. Call generate_commitment() first.")
        
        # Compute response
        response = (
            self.random_nonce + challenge * self.secret
        ) % (self.PRIME - 1)
        
        return response
    
    def create_proof(self, challenge):
        """
        Create complete proof for given challenge.
        
        Parameters:
            challenge: Integer c from verifier
        
        Returns:
            dict with commitment, response, public_value
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
        Clear sensitive data from memory.
        Call after verification is complete.
        """
        self.secret = None
        self.random_nonce = None
        self.commitment = None
    
    @staticmethod
    def get_prime():
        """Return the prime modulus."""
        return ForensicsProver.PRIME
    
    @staticmethod
    def get_generator():
        """Return the generator."""
        return ForensicsProver.GENERATOR