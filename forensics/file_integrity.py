"""
Zero Knowledge Proof - File Integrity Flow Module
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensics.prover import ForensicsProver
from forensics.verifier import ForensicsVerifier
from performance.metrics import get_tracker


class ZKPFileIntegritySystem:
    
    def __init__(self):
        self.prover = ForensicsProver()
        self.verifier = ForensicsVerifier()
        self.tracker = get_tracker()
        self.is_registered = False
        self.registered_file_name = None
    
    def get_file_path_from_user(self, prompt="Enter file path: "):
        print(prompt, end="")
        file_path = input().strip()
        
        file_path = file_path.strip('"').strip("'")
        
        if not os.path.exists(file_path):
            print(f"Error: File not found: {file_path}")
            return None
        
        if not os.path.isfile(file_path):
            print(f"Error: Path is not a file: {file_path}")
            return None
        
        return file_path
    
    def register_evidence(self, file_path=None):
        print("\n" + "=" * 50)
        print("EVIDENCE REGISTRATION")
        print("=" * 50)
        
        if file_path is None:
            print("Select the ORIGINAL evidence file.")
            file_path = self.get_file_path_from_user("File path: ")
        
        if file_path is None:
            return False
        
        try:
            self.prover.load_file(file_path)
            public_value = self.prover.get_public_value()
            metadata = self.prover.get_file_metadata()
            
            self.verifier.register_evidence(
                public_value=public_value,
                evidence_id=f"EVD_{metadata['file_name']}"
            )
            
            self.is_registered = True
            self.registered_file_name = metadata['file_name']
            
            print("\nEvidence registered successfully.")
            print(f"  File Name: {metadata['file_name']}")
            print(f"  File Size: {metadata['file_size_formatted']}")
            print("  File content was NOT stored.")
            print("=" * 50)
            
            return True
            
        except FileNotFoundError as e:
            print(f"Error: {e}")
            return False
        except Exception as e:
            print(f"Error processing file: {e}")
            return False
    
    def verify_integrity(self, file_path=None, file_bytes=None, file_name=None):
        if not self.is_registered:
            print("Error: No evidence registered. Please register first.")
            return False, 0, 0
        
        print("\n" + "=" * 50)
        print("FILE INTEGRITY VERIFICATION")
        print("=" * 50)
        
        verify_prover = ForensicsProver()
        
        try:
            if file_bytes is not None:
                verify_prover.load_file_bytes(file_bytes, file_name or "uploaded_file")
            elif file_path is not None:
                verify_prover.load_file(file_path)
            else:
                print("Select the file to VERIFY.")
                file_path = self.get_file_path_from_user("File path: ")
                
                if file_path is None:
                    return False, 0, 0
                
                verify_prover.load_file(file_path)
            
            metadata = verify_prover.get_file_metadata()
            print(f"\nVerifying: {metadata['file_name']}")
            print(f"Size: {metadata['file_size_formatted']}")
            
        except Exception as e:
            print(f"Error loading file: {e}")
            return False, 0, 0
        
        print("\nGenerating zero knowledge proof...")
        
        self.tracker.start_timer()
        
        commitment = verify_prover.generate_commitment()
        challenge = self.verifier.generate_challenge()
        response = verify_prover.generate_response(challenge)
        
        proof_time = self.tracker.stop_timer()
        
        print("Proof generated.")
        
        print("\nVerifying proof...")
        
        self.tracker.start_timer()
        
        # FIXED: Use None to force comparison with REGISTERED public value
        is_valid = self.verifier.verify_proof(
            commitment=commitment,
            response=response,
            public_value=None
        )
        
        verify_time = self.tracker.stop_timer()
        
        status = self.verifier.get_verification_status(is_valid)
        detailed = self.verifier.get_detailed_status(is_valid)
        
        print(f"\nResult: {status}")
        print(f"Conclusion: {detailed['conclusion']}")
        
        self.tracker.log_result(
            use_case="forensics",
            operation="proof_generation",
            time_seconds=proof_time,
            status=status
        )
        
        self.tracker.log_result(
            use_case="forensics",
            operation="verification",
            time_seconds=verify_time,
            status=status
        )
        
        self.tracker.print_metrics(
            use_case="File Integrity Verification",
            proof_time=proof_time,
            verify_time=verify_time,
            status=status
        )
        
        verify_prover.clear_secret()
        
        return is_valid, proof_time, verify_time
    
    def create_test_files(self):
        temp_dir = tempfile.mkdtemp(prefix="zkp_demo_")
        
        original_content = b"This is the original evidence file.\n"
        original_content += b"Case Number: 2026-ZKP-001\n"
        
        original_path = os.path.join(temp_dir, "original_evidence.txt")
        with open(original_path, "wb") as f:
            f.write(original_content)
        
        modified_content = b"This is the original evidence file.\n"
        modified_content += b"Case Number: 2026-ZKP-001\n"
        modified_content += b"TAMPERED LINE\n"
        
        modified_path = os.path.join(temp_dir, "modified_evidence.txt")
        with open(modified_path, "wb") as f:
            f.write(modified_content)
        
        return original_path, modified_path, temp_dir
    
    def run_automated_demo(self):
        print("\nCreating test files...")
        
        original_path, modified_path, temp_dir = self.create_test_files()
        
        print(f"Test files created in: {temp_dir}")
        
        print("\n" + "=" * 50)
        print("STEP 1: Register Original Evidence")
        print("=" * 50)
        self.register_evidence(original_path)
        
        print("\n" + "=" * 50)
        print("STEP 2: Verify Original File (Should PASS)")
        print("=" * 50)
        result1, _, _ = self.verify_integrity(original_path)
        
        print("\n" + "=" * 50)
        print("STEP 3: Verify Modified File (Should FAIL)")
        print("=" * 50)
        result2, _, _ = self.verify_integrity(modified_path)
        
        print("\n" + "=" * 50)
        print("SUMMARY")
        print("=" * 50)
        print(f"Original file: {'PASSED' if result1 else 'FAILED'}")
        print(f"Modified file: {'PASSED' if result2 else 'FAILED'}")
        print(f"Test Status: {'SUCCESS' if result1 and not result2 else 'CHECK RESULTS'}")


def run_forensics_demo():
    system = ZKPFileIntegritySystem()
    
    print("\nSelect mode:")
    print("1. Automated (test files)")
    print("2. Interactive (your files)")
    
    choice = input("Enter choice (1 or 2): ").strip()
    
    if choice == "2":
        print("\nPHASE 1: Register Original File")
        system.register_evidence()
        
        if system.is_registered:
            print("\nPHASE 2: Verify Same File (Should PASS)")
            system.verify_integrity()
            
            print("\nPHASE 3: Verify Different File (Should FAIL)")
            system.verify_integrity()
    else:
        system.run_automated_demo()


if __name__ == "__main__":
    run_forensics_demo()