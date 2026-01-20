"""
Zero Knowledge Proof Capstone Project - Main Demo
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from authentication.auth_flow import ZKPAuthenticationSystem
from forensics.file_integrity import ZKPFileIntegritySystem
from performance.metrics import get_tracker


def print_header():
    print()
    print("=" * 60)
    print("  ZERO KNOWLEDGE PROOF CRYPTOGRAPHIC SYSTEM")
    print()


def run_authentication_demo():
    print()
    print("#" * 60)
    print("  USE CASE 1: ZKP AUTHENTICATION")
    print("#" * 60)
    
    auth_system = ZKPAuthenticationSystem()
    
    print("\nPHASE 1: REGISTRATION")
    print("-" * 40)
    registration_success = auth_system.register()
    
    if not registration_success:
        print("Registration failed.")
        return
    
    print("\nPHASE 2: CORRECT PASSWORD (Should VERIFY)")
    print("-" * 40)
    auth_system.authenticate()
    
    print("\nPHASE 3: WRONG PASSWORD (Should REJECT)")
    print("-" * 40)
    auth_system.authenticate()


def run_forensics_demo():
    print()
    print("#" * 60)
    print("  USE CASE 2: FILE INTEGRITY VERIFICATION")
    print("#" * 60)
    
    forensics_system = ZKPFileIntegritySystem()
    
    print("\nSelect mode:")
    print("1. Automated (test files)")
    print("2. Interactive (your files)")
    
    choice = input("Enter choice (1 or 2): ").strip()
    
    if choice == "2":
        print("\nPHASE 1: REGISTER ORIGINAL FILE")
        print("-" * 40)
        reg_success = forensics_system.register_evidence()
        
        if not reg_success:
            print("Registration failed.")
            return
        
        print("\nPHASE 2: VERIFY SAME FILE (Should PASS)")
        print("-" * 40)
        forensics_system.verify_integrity()
        
        print("\nPHASE 3: VERIFY DIFFERENT FILE (Should FAIL)")
        print("-" * 40)
        forensics_system.verify_integrity()
    else:
        forensics_system.run_automated_demo()


def main():
    try:
        print_header()
        
        print("SELECT DEMO:")
        print("1. Run BOTH use cases")
        print("2. Authentication only")
        print("3. File Integrity only")
        print("4. Exit")
        print()
        
        choice = input("Enter choice (1-4): ").strip()
        
        if choice == "1":
            run_authentication_demo()
            input("\nPress Enter to continue...")
            run_forensics_demo()
        elif choice == "2":
            run_authentication_demo()
        elif choice == "3":
            run_forensics_demo()
        elif choice == "4":
            print("Exiting.")
            return
        else:
            run_authentication_demo()
            input("\nPress Enter to continue...")
            run_forensics_demo()
        
        print("\n" + "=" * 60)
        print("DEMO COMPLETE")
        print("=" * 60)
        
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except Exception as e:
        print(f"\nError: {e}")


if __name__ == "__main__":
    main()