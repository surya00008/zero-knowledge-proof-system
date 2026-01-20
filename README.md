# 🔐 Zero Knowledge Proof Cryptographic System

### Secure Authentication & Integrity Verification Using Zero Knowledge Proofs

---

## 📋 Project Overview

This project demonstrates a **practical implementation of Zero Knowledge Proof (ZKP)** cryptographic algorithms using a **Schnorr-like protocol**, applied to real-world security use cases.

The system shows how secrets can be **cryptographically proven** without ever being transmitted or stored.

### Implemented Use Cases
1. **Secure Authentication** — prove password knowledge without revealing it  
2. **Digital Forensics** — verify file integrity without exposing file contents  

---

## 🎯 Problem Statement

### Issues with Traditional Authentication
- Passwords are transmitted over networks
- Servers store password hashes that may be leaked
- Man-in-the-middle attacks can capture credentials
- Data breaches expose sensitive secrets

### Proposed Solution
**Zero Knowledge Proof–based authentication**  
A cryptographic approach that allows a user to prove knowledge of a secret **without ever revealing the secret itself**.

---

## 📐 Mathematical Foundation

### Schnorr-like Zero Knowledge Proof Protocol

The implementation is based on a **Schnorr-style ZKP** using the discrete logarithm problem.

```
Parameters:
- p = 256-bit prime number (secp256k1 prime)
- g = 2 (generator)
- x = secret (derived from password/file hash via SHA-256)
- y = g^x mod p (public value - safe to share)
```

### Protocol Steps:

```
┌─────────────────┐                    ┌─────────────────┐
│     PROVER      │                    │    VERIFIER     │
│   (Client)      │                    │    (Server)     │
└────────┬────────┘                    └────────┬────────┘
         │                                      │
         │  1. Commitment: t = g^r mod p        │
         │ ────────────────────────────────────>│
         │                                      │
         │  2. Challenge: c (random)            │
         │ <────────────────────────────────────│
         │                                      │
         │  3. Response: s = r + c*x mod (p-1)  │
         │ ────────────────────────────────────>│
         │                                      │
         │  4. Verify: g^s ≟ t * y^c mod p      │
         │                                      │
```

### Why This is Zero Knowledge:

| Transmitted (Safe) | Never Transmitted|
|--------------------|------------------|
| Commitment (t)     | Password         |
| Challenge (c)      | Secret (x)       |
| Response (s)       | Random nonce (r) |
| Public value (y)   | File contents    |

**Security Basis:** Discrete Logarithm Problem - Computing x from y = g^x mod p is computationally infeasible.

---

## 🏗️ Project Architecture

```
zkp-capstone-final/
│
├── main.py                 # CLI demo runner
├── requirements.txt        # Python dependencies
├── README.md               # This documentation
│
├── authentication/         # Use Case 1: ZKP Authentication
│   ├── __init__.py
│   ├── prover.py          # Prover: generates proofs
│   ├── verifier.py        # Verifier: validates proofs
│   └── auth_flow.py       # Complete auth workflow
│
├── forensics/             # Use Case 2: File Integrity
│   ├── __init__.py
│   ├── prover.py          # Prover: file-based proofs
│   ├── verifier.py        # Verifier: validates file proofs
│   └── file_integrity.py  # Complete file verification flow
│
├── performance/           # Performance Measurement
│   ├── __init__.py
│   ├── metrics.py         # Timing and logging utilities
│   └── results.csv        # Performance data log
│
├── ui/                    # Streamlit Web Interface
│   └── app.py             # Full-featured web UI
│
└── docs/                  # Documentation
    ├── PRESENTATION_GUIDE.md  # How to present the project
    └── ARCHITECTURE.md        # Technical details
```

---

## 🚀 How to Run

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation

```bash
# 1. Navigate to project folder
cd zkp-capstone-final

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run CLI demo
python main.py

# 4. Run Web Interface (RECOMMENDED for presentation)
streamlit run ui/app.py
```

---

## 💻 Use Cases

### Use Case 1: ZKP Authentication

**Scenario:** Login to a system without transmitting your password.

**Traditional Method (INSECURE):**
```
User → "password123" → Server → Compare with stored hash
❌ Password transmitted
❌ Server sees password
```

**ZKP Method (SECURE):**
```
User → Mathematical Proof → Server → Verify equation
✅ Password NEVER transmitted
✅ Server NEVER sees password
✅ Even if hacked, no passwords leaked
```

### Use Case 2: Digital Forensics File Integrity

**Scenario:** Prove you have an authentic copy of evidence without sending the file.

**Applications:**
- Court evidence verification
- Chain of custody in forensics
- Secure backup verification
- Distributed file validation

---

## 📊 Performance Results

Our system demonstrates excellent performance:

| Operation          | Average Time |
|--------------------|--------------|
| Proof Generation   | < 1 ms       |
| Verification       | < 1 ms       |
| Total Round-trip   | < 2 ms       |

*Based on 256-bit prime modular exponentiation*

---

## 🔒 Security Properties

### 1. Completeness
If the prover knows the secret, verification always succeeds.

### 2. Soundness
If the prover does NOT know the secret, they cannot forge a valid proof (probability ≈ 1/p ≈ 0).

### 3. Zero Knowledge
The verifier learns NOTHING about the secret from the proof values.

---

## 🛠️ Technology Stack

| Component    | Technology                  |
| ------------ | --------------------------- |
| Language     | Python 3.8+                 |
| Cryptography | SHA-256, Modular Arithmetic |
| Protocol     | Schnorr-like ZKP            |
| Web UI       | Streamlit                   |
| Logging      | CSV                         |

---

## 📚 References

1. Schnorr, C.P. (1991). Efficient signature generation by smart cards. *Journal of Cryptology*
2. Goldwasser, S., Micali, S., & Rackoff, C. (1989). The knowledge complexity of interactive proof systems. *SIAM Journal on Computing*
3. RFC 8235 - Schnorr Non-interactive Zero-Knowledge Proof

---


---

## ✅ Features

- [x] Schnorr-like ZKP Protocol
- [x] Secure Password Authentication
- [x] File Integrity Verification
- [x] Command-line Interface (CLI)
- [x] Web-based User Interface (Streamlit)
- [x] Performance Metrics Logging
- [x] Comparative Demo (Traditional vs ZKP)
- [x] Mathematical Visualization

---

*© 2026 Capstone Project - Zero Knowledge Proof System*
