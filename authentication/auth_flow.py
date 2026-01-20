"""
Zero Knowledge Proof - Authentication Flow Module
"""

import getpass
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authentication.prover import AuthenticationProver
from authentication.verifier import AuthenticationVerifier
from performance.metrics import get_tracker


class ZKPAuthenticationSystem:
    
    def __init__(self):
        self.prover = AuthenticationProver()
        self.verifier = AuthenticationVerifier()
        self.tracker = get_tracker()
        self.is_registered = False
    
    def secure_password_input(self, prompt="Enter password: "):
        try:
            password = getpass.getpass(prompt)
            return password
        except Exception as e:
            print(f"Error reading password: {e}")
            return None
    
    def register(self, password=None):
        print("\n" + "=" * 50)
        print("USER REGISTRATION")
        print("=" * 50)
        
        if password is None:
            print("Password input is hidden for security.")
            password = self.secure_password_input("Enter registration password: ")
        
        if password is None or len(password) == 0:
            print("Error: Password cannot be empty.")
            return False
        
        self.prover.set_secret(password)
        public_value = self.prover.get_public_value()
        self.verifier.register_public_value(public_value)
        
        self.is_registered = True
        print("Registration successful.")
        print("Public value computed and stored.")
        print("Password was NOT stored.")
        print("=" * 50)
        
        return True
    
    def authenticate(self, password=None):
        if not self.is_registered:
            print("Error: No user registered. Please register first.")
            return False, 0, 0
        
        print("\n" + "=" * 50)
        print("ZKP AUTHENTICATION")
        print("=" * 50)
        
        if password is None:
            print("Password input is hidden for security.")
            password = self.secure_password_input("Enter authentication password: ")
        
        if password is None:
            print("Error: Password input failed.")
            return False, 0, 0
        
        auth_prover = AuthenticationProver()
        
        print("\nGenerating zero knowledge proof...")
        
        self.tracker.start_timer()
        
        auth_prover.set_secret(password)
        commitment = auth_prover.generate_commitment()
        challenge = self.verifier.generate_challenge()
        response = auth_prover.generate_response(challenge)
        
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
        
        print(f"\nResult: {status}")
        
        self.tracker.log_result(
            use_case="authentication",
            operation="proof_generation",
            time_seconds=proof_time,
            status=status
        )
        
        self.tracker.log_result(
            use_case="authentication",
            operation="verification",
            time_seconds=verify_time,
            status=status
        )
        
        self.tracker.print_metrics(
            use_case="ZKP Authentication",
            proof_time=proof_time,
            verify_time=verify_time,
            status=status
        )
        
        auth_prover.clear_secret()
        
        return is_valid, proof_time, verify_time
    
    def demonstrate_success_and_failure(self):
        print("\n" + "#" * 60)
        print("ZKP AUTHENTICATION DEMONSTRATION")
        print("#" * 60)
        
        print("\nPHASE 1: Registration")
        print("-" * 40)
        self.register()
        
        print("\nPHASE 2: Correct Password Authentication")
        print("-" * 40)
        print("(Enter the SAME password you registered with)")
        self.authenticate()
        
        print("\nPHASE 3: Wrong Password Authentication")
        print("-" * 40)
        print("(Enter a DIFFERENT password to see rejection)")
        self.authenticate()
        
        print("\n" + "#" * 60)
        print("DEMONSTRATION COMPLETE")
        print("#" * 60)


def run_authentication_demo():
    system = ZKPAuthenticationSystem()
    system.demonstrate_success_and_failure()


if __name__ == "__main__":
    run_authentication_demo()