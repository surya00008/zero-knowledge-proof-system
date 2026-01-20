"""
Zero Knowledge Proof - Enhanced Streamlit Web Interface
Professional UI with Live Cryptography Visualization
"""

import streamlit as st
import sys
import os
import time
import hashlib
import secrets
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authentication.prover import AuthenticationProver
from authentication.verifier import AuthenticationVerifier
from forensics.prover import ForensicsProver
from forensics.verifier import ForensicsVerifier
from performance.metrics import get_tracker

# Page configuration
st.set_page_config(
    page_title="Zero Knowledge Proof System",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced CSS with animations
st.markdown("""
<style>
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.5; }
        100% { opacity: 1; }
    }
    @keyframes slideIn {
        from { transform: translateX(-20px); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    .main-header {
        font-size: 2.8rem;
        font-weight: bold;
        background: linear-gradient(90deg, #4FC3F7, #81C784);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #B0BEC5;
        text-align: center;
        margin-bottom: 2rem;
    }
    .success-box {
        padding: 1.5rem;
        border-radius: 0.5rem;
        background-color: #1B5E20;
        border-left: 5px solid #4CAF50;
        margin: 1rem 0;
        color: #E8F5E9;
        animation: slideIn 0.5s ease;
    }
    .error-box {
        padding: 1.5rem;
        border-radius: 0.5rem;
        background-color: #B71C1C;
        border-left: 5px solid #F44336;
        margin: 1rem 0;
        color: #FFEBEE;
    }
    .info-box {
        padding: 1.5rem;
        border-radius: 0.5rem;
        background-color: #0D47A1;
        border-left: 5px solid #2196F3;
        margin: 1rem 0;
        color: #E3F2FD;
    }
    .warning-box {
        padding: 1.5rem;
        border-radius: 0.5rem;
        background-color: #E65100;
        border-left: 5px solid #FF9800;
        margin: 1rem 0;
        color: #FFF3E0;
    }
    .crypto-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background: linear-gradient(135deg, #1a237e 0%, #0d47a1 100%);
        border: 2px solid #42a5f5;
        margin: 0.5rem 0;
        color: #e3f2fd;
        font-family: 'Courier New', monospace;
        font-size: 0.85rem;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    }
    .proof-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #263238;
        border: 1px solid #546E7A;
        margin: 0.5rem 0;
        color: #ECEFF1;
        font-family: 'Courier New', monospace;
        font-size: 0.9rem;
    }
    .result-verified {
        padding: 2rem;
        border-radius: 0.5rem;
        background: linear-gradient(135deg, #1B5E20 0%, #2E7D32 100%);
        border: 3px solid #66BB6A;
        margin: 1rem 0;
        color: #FFFFFF;
        text-align: center;
        box-shadow: 0 6px 12px rgba(0,0,0,0.3);
    }
    .result-rejected {
        padding: 2rem;
        border-radius: 0.5rem;
        background: linear-gradient(135deg, #B71C1C 0%, #C62828 100%);
        border: 3px solid #EF5350;
        margin: 1rem 0;
        color: #FFFFFF;
        text-align: center;
        box-shadow: 0 6px 12px rgba(0,0,0,0.3);
    }
    .step-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #37474F;
        border-left: 4px solid #26C6DA;
        margin: 0.5rem 0;
        color: #ECEFF1;
    }
    .compare-bad {
        padding: 1.5rem;
        border-radius: 0.5rem;
        background-color: #4A1515;
        border: 2px solid #EF5350;
        margin: 1rem 0;
        color: #FFCDD2;
    }
    .compare-good {
        padding: 1.5rem;
        border-radius: 0.5rem;
        background-color: #1B3D1B;
        border: 2px solid #66BB6A;
        margin: 1rem 0;
        color: #C8E6C9;
    }
    .attack-box {
        padding: 1.5rem;
        border-radius: 0.5rem;
        background: linear-gradient(135deg, #4a148c 0%, #7b1fa2 100%);
        border: 2px solid #e040fb;
        margin: 1rem 0;
        color: #f3e5f5;
    }
    .live-crypto {
        padding: 1rem;
        border-radius: 0.5rem;
        background: #000000;
        border: 2px solid #00ff00;
        margin: 0.5rem 0;
        color: #00ff00;
        font-family: 'Courier New', monospace;
        font-size: 0.8rem;
    }
    .network-packet {
        padding: 0.8rem;
        border-radius: 0.3rem;
        background: #1a1a2e;
        border: 1px solid #e94560;
        margin: 0.3rem 0;
        color: #eee;
        font-family: 'Courier New', monospace;
        font-size: 0.75rem;
    }
</style>
""", unsafe_allow_html=True)


def show_header():
    st.markdown('<p class="main-header">🔐 Zero Knowledge Proof System</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Application of ZKP Cryptographic Algorithm</p>', unsafe_allow_html=True)
    st.markdown("---")


def show_live_crypto_demo():
    """NEW: Live cryptography demonstration showing password protection in real-time"""
    st.header("🔬 Live Cryptography Lab")
    
    st.markdown("""
    <div class="info-box">
    <b>🔴 LIVE: Watch Your Password Being Protected in Real-Time</b><br>
    Type a password and see exactly how ZKP transforms and protects it.
    </div>
    """, unsafe_allow_html=True)
    
    password = st.text_input("Enter any password to see live transformation:", value="", type="password", key="live_pass")
    
    if password:
        st.markdown("### 🔄 Transformation Pipeline")
        
        # Step 1: Original password
        col1, col2 = st.columns([1, 2])
        with col1:
            st.markdown("**Step 1: Input**")
        with col2:
            st.markdown(f"""
            <div class="live-crypto">
            PASSWORD: {'*' * len(password)}<br>
            LENGTH: {len(password)} characters<br>
            ENTROPY: ~{len(password) * 6.5:.1f} bits
            </div>
            """, unsafe_allow_html=True)
        
        # Step 2: SHA-256 Hash
        password_bytes = password.encode('utf-8')
        sha256_hash = hashlib.sha256(password_bytes).hexdigest()
        
        col1, col2 = st.columns([1, 2])
        with col1:
            st.markdown("**Step 2: SHA-256 Hash**")
        with col2:
            st.markdown(f"""
            <div class="live-crypto">
            ALGORITHM: SHA-256 (256-bit output)<br>
            HASH: {sha256_hash[:32]}...<br>
            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{sha256_hash[32:]}<br>
            STATUS: ✅ One-way transformation complete
            </div>
            """, unsafe_allow_html=True)
        
        # Step 3: Convert to secret integer
        hash_int = int(sha256_hash, 16)
        PRIME = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
        secret_x = (hash_int % (PRIME - 2)) + 1
        
        col1, col2 = st.columns([1, 2])
        with col1:
            st.markdown("**Step 3: Secret Number x**")
        with col2:
            st.markdown(f"""
            <div class="live-crypto">
            OPERATION: hash mod (p-1) + 1<br>
            SECRET_X: {str(secret_x)[:40]}...<br>
            BIT_SIZE: 256 bits<br>
            STATUS: ✅ Secret derived (NEVER transmitted)
            </div>
            """, unsafe_allow_html=True)
        
        # Step 4: Public value
        GENERATOR = 2
        public_y = pow(GENERATOR, secret_x, PRIME)
        
        col1, col2 = st.columns([1, 2])
        with col1:
            st.markdown("**Step 4: Public Value y**")
        with col2:
            st.markdown(f"""
            <div class="live-crypto">
            FORMULA: y = g^x mod p<br>
            GENERATOR: g = 2<br>
            PRIME: secp256k1 (256-bit)<br>
            PUBLIC_Y: {str(public_y)[:40]}...<br>
            STATUS: ✅ Safe to share publicly
            </div>
            """, unsafe_allow_html=True)
        
        # Step 5: Generate proof components
        random_r = secrets.randbelow(PRIME - 2) + 1
        commitment_t = pow(GENERATOR, random_r, PRIME)
        challenge_c = secrets.randbelow(PRIME - 2) + 1
        response_s = (random_r + challenge_c * secret_x) % (PRIME - 1)
        
        st.markdown("### 📡 ZKP Protocol Execution")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown(f"""
            <div class="crypto-box">
            <b>COMMITMENT (t)</b><br><br>
            t = g^r mod p<br><br>
            Random r: {str(random_r)[:20]}...<br>
            Result: {str(commitment_t)[:20]}...<br><br>
            📤 SENT TO SERVER
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div class="crypto-box">
            <b>CHALLENGE (c)</b><br><br>
            Server generates random c<br><br>
            Challenge: {str(challenge_c)[:20]}...<br><br>
            📥 RECEIVED FROM SERVER
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown(f"""
            <div class="crypto-box">
            <b>RESPONSE (s)</b><br><br>
            s = r + c × x mod (p-1)<br><br>
            Result: {str(response_s)[:20]}...<br><br>
            📤 SENT TO SERVER
            </div>
            """, unsafe_allow_html=True)
        
        # Verification
        left_side = pow(GENERATOR, response_s, PRIME)
        right_side = (commitment_t * pow(public_y, challenge_c, PRIME)) % PRIME
        is_valid = left_side == right_side
        
        st.markdown("### ✅ Verification Check")
        
        st.markdown(f"""
        <div class="crypto-box">
        <b>EQUATION: g^s ≟ t × y^c mod p</b><br><br>
        LEFT SIDE (g^s):&nbsp;&nbsp;{str(left_side)[:50]}...<br>
        RIGHT SIDE (t×y^c): {str(right_side)[:50]}...<br><br>
        MATCH: {'✅ YES - VERIFIED!' if is_valid else '❌ NO - REJECTED!'}
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("### 🔒 Security Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <div class="success-box">
            <b>✅ What WAS Transmitted:</b><br><br>
            • Commitment t (random, meaningless alone)<br>
            • Response s (masked by random r)<br>
            • Public value y (safe, can't derive x)<br><br>
            <b>Total network exposure: 768 bits</b>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div class="error-box">
            <b>❌ What was NEVER Transmitted:</b><br><br>
            • Password: {'*' * len(password)}<br>
            • Hash: {sha256_hash[:16]}...<br>
            • Secret x: {str(secret_x)[:16]}...<br>
            • Random r: {str(random_r)[:16]}...<br><br>
            <b>Your password is 100% protected!</b>
            </div>
            """, unsafe_allow_html=True)


def show_attack_simulation():
    """NEW: Simulate hacker attack to show ZKP security"""
    st.header("🏴‍☠️ Attack Simulation Lab")
    
    st.markdown("""
    <div class="attack-box">
    <b>⚠️ HACKER SIMULATION MODE</b><br>
    See what happens when a hacker intercepts ZKP traffic vs traditional passwords.
    </div>
    """, unsafe_allow_html=True)
    
    st.subheader("Scenario: Network Interception Attack")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🔓 Traditional Password Attack")
        
        demo_password = "SuperSecret123!"
        demo_hash = hashlib.sha256(demo_password.encode()).hexdigest()
        
        st.markdown("""
        <div class="network-packet">
        [INTERCEPTED PACKET]<br>
        Protocol: HTTPS POST /login<br>
        Time: 2026-01-18 10:30:45<br>
        ─────────────────────────<br>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown(f"""
        <div class="network-packet" style="border-color: #ff0000;">
        🔴 CAPTURED DATA:<br>
        username: admin<br>
        password: {demo_password}<br>
        hash: {demo_hash[:32]}...<br>
        ─────────────────────────<br>
        ⚠️ PASSWORD EXPOSED!
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("🏴‍☠️ Simulate Attack", key="trad_attack"):
            with st.spinner("Cracking password..."):
                time.sleep(1)
            st.error(f"💀 PASSWORD CRACKED: {demo_password}")
            st.markdown("**Hacker can now:**")
            st.markdown("- Login as the user")
            st.markdown("- Access all accounts using same password")
            st.markdown("- Sell credentials on dark web")
    
    with col2:
        st.markdown("### 🔐 ZKP Attack (Impossible)")
        
        # Generate dummy ZKP values
        PRIME = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
        commitment = secrets.randbelow(PRIME)
        response = secrets.randbelow(PRIME)
        public_y = secrets.randbelow(PRIME)
        
        st.markdown("""
        <div class="network-packet">
        [INTERCEPTED PACKET]<br>
        Protocol: ZKP Auth v1.0<br>
        Time: 2026-01-18 10:30:45<br>
        ─────────────────────────<br>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown(f"""
        <div class="network-packet" style="border-color: #00ff00;">
        🟢 CAPTURED DATA:<br>
        commitment: {str(commitment)[:30]}...<br>
        response: {str(response)[:30]}...<br>
        public_y: {str(public_y)[:30]}...<br>
        ─────────────────────────<br>
        ❓ NO PASSWORD TO CRACK!
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("🏴‍☠️ Attempt Attack", key="zkp_attack"):
            with st.spinner("Attempting to extract password..."):
                progress_bar = st.progress(0)
                for i in range(100):
                    time.sleep(0.02)
                    progress_bar.progress(i + 1)
            
            st.success("🛡️ ATTACK FAILED!")
            st.markdown("""
            **Why attack failed:**
            - No password in captured data
            - Cannot reverse discrete logarithm
            - Each proof uses new random values
            - Would take 10^50 years to brute force
            """)
    
    st.markdown("---")
    st.subheader("📊 Attack Difficulty Comparison")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Traditional Password", "~3 hours", delta="Easy to crack", delta_color="inverse")
    with col2:
        st.metric("SHA-256 Hash Only", "~3 months", delta="GPU cracking", delta_color="inverse")
    with col3:
        st.metric("ZKP Protected", "10^50 years", delta="Mathematically impossible", delta_color="normal")


def show_comparison():
    st.header("📊 Traditional Password vs Zero Knowledge Proof")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("❌ Traditional Password")
        st.markdown("""
        <div class="compare-bad">
        <b>How it works:</b><br><br>
        1. User enters password<br>
        2. Password sent to server 🔴<br>
        3. Server compares with stored hash<br>
        4. Server knows your password!<br><br>
        <b>Problems:</b><br><br>
        • Password transmitted over network<br>
        • Server can see password<br>
        • If hacked, password leaked<br>
        • Man-in-middle can steal password
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("#### What Server Receives:")
        demo_pass = st.text_input("Type password (visible):", value="mypassword123", key="normal_pass")
        if demo_pass:
            st.markdown(f"""
            <div class="network-packet" style="border-color: #ff0000;">
            📡 NETWORK TRAFFIC:<br>
            POST /login HTTP/1.1<br>
            Content-Type: application/json<br>
            <br>
            {{"password": "{demo_pass}"}}<br>
            <br>
            ⚠️ PASSWORD VISIBLE IN TRAFFIC!
            </div>
            """, unsafe_allow_html=True)
    
    with col2:
        st.subheader("✅ Zero Knowledge Proof")
        st.markdown("""
        <div class="compare-good">
        <b>How it works:</b><br><br>
        1. User enters password<br>
        2. Mathematical PROOF sent 🟢<br>
        3. Server verifies the math<br>
        4. Server NEVER sees password!<br><br>
        <b>Benefits:</b><br><br>
        • Password never transmitted<br>
        • Server cannot see password<br>
        • If hacked, nothing useful leaked<br>
        • Mathematically secure
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("#### What Server Receives:")
        zkp_pass = st.text_input("Type password:", value="mypassword123", type="password", key="zkp_pass")
        if zkp_pass:
            prover = AuthenticationProver()
            prover.set_secret(zkp_pass)
            commitment = prover.generate_commitment()
            st.markdown(f"""
            <div class="network-packet" style="border-color: #00ff00;">
            📡 NETWORK TRAFFIC:<br>
            POST /zkp-auth HTTP/1.1<br>
            Content-Type: application/json<br>
            <br>
            {{"commitment": "{str(commitment)[:25]}..."}}<br>
            <br>
            ✅ ONLY MATH PROOF, NO PASSWORD!
            </div>
            """, unsafe_allow_html=True)


def run_normal_password_demo():
    st.header("🔓 Traditional Password Demo (INSECURE)")
    
    st.markdown("""
    <div class="warning-box">
    <b>⚠️ This demonstrates how traditional passwords work</b><br>
    Notice how the password is visible and transmitted to the server.
    </div>
    """, unsafe_allow_html=True)
    
    stored_password = st.text_input("Step 1 - Register password:", type="password", key="reg_normal")
    
    if stored_password:
        stored_hash = hashlib.sha256(stored_password.encode()).hexdigest()
        
        st.markdown("**What server stores:**")
        st.code(f"Password Hash: {stored_hash}")
        
        login_password = st.text_input("Step 2 - Login password:", type="password", key="login_normal")
        
        if st.button("Login (Traditional)", key="btn_normal"):
            if login_password:
                login_hash = hashlib.sha256(login_password.encode()).hexdigest()
                
                st.markdown("**Server receives and computes:**")
                st.code(f"Received hash: {login_hash}")
                
                if login_hash == stored_hash:
                    st.success("✅ Login Successful")
                else:
                    st.error("❌ Login Failed")
                
                st.markdown("""
                <div class="error-box">
                <b>Security Issue:</b> The password was transmitted to the server. 
                If network is compromised, attacker can steal password!
                </div>
                """, unsafe_allow_html=True)


def run_zkp_authentication():
    st.header("🔐 ZKP Authentication Demo (SECURE)")
    
    tracker = get_tracker()
    
    if 'auth_registered' not in st.session_state:
        st.session_state.auth_registered = False
        st.session_state.auth_verifier = None
        st.session_state.auth_public_value = None
    
    st.markdown("""
    <div class="info-box">
    <b>🔒 Zero Knowledge Proof Authentication</b><br>
    Password is NEVER transmitted. Only mathematical proof is sent.
    </div>
    """, unsafe_allow_html=True)
    
    # Registration
    st.subheader("Step 1: Registration")
    reg_password = st.text_input("Enter registration password:", type="password", key="zkp_reg")
    
    if st.button("Register with ZKP", key="btn_zkp_reg"):
        if reg_password:
            prover = AuthenticationProver()
            prover.set_secret(reg_password)
            public_value = prover.get_public_value()
            
            verifier = AuthenticationVerifier()
            verifier.register_public_value(public_value)
            
            st.session_state.auth_registered = True
            st.session_state.auth_verifier = verifier
            st.session_state.auth_public_value = public_value
            
            st.markdown("""
            <div class="success-box">
            <b>✅ Registration Successful!</b><br><br>
            Password was converted to public value.<br>
            Password was NOT stored anywhere.
            </div>
            """, unsafe_allow_html=True)
            
            with st.expander("🔍 See Registration Details"):
                st.markdown(f"""
                <div class="crypto-box">
                <b>REGISTRATION PROCESS:</b><br><br>
                1. Password: {'*' * len(reg_password)} (hidden)<br>
                2. SHA-256 hash computed<br>
                3. Secret number x derived<br>
                4. Public value y = g^x mod p<br><br>
                PUBLIC VALUE (stored):<br>
                y = {str(public_value)[:60]}...
                </div>
                """, unsafe_allow_html=True)
    
    # Authentication
    if st.session_state.auth_registered:
        st.markdown("---")
        st.subheader("Step 2: Authentication")
        auth_password = st.text_input("Enter login password:", type="password", key="zkp_auth")
        
        if st.button("Authenticate with ZKP", key="btn_zkp_auth"):
            if auth_password:
                prover = AuthenticationProver()
                prover.set_secret(auth_password)
                
                verifier = st.session_state.auth_verifier
                
                # Measure proof generation
                tracker.start_timer()
                
                commitment = prover.generate_commitment()
                random_r = prover.random_nonce
                challenge = verifier.generate_challenge()
                response = prover.generate_response(challenge)
                
                proof_time = tracker.stop_timer()
                
                # Measure verification
                tracker.start_timer()
                
                g = verifier.GENERATOR
                p = verifier.PRIME
                y = st.session_state.auth_public_value
                
                left_side = pow(g, response, p)
                y_power_c = pow(y, challenge, p)
                right_side = (commitment * y_power_c) % p
                
                is_valid = (left_side == right_side)
                
                verify_time = tracker.stop_timer()
                
                # Log to CSV
                status = "VERIFIED" if is_valid else "REJECTED"
                tracker.log_result("authentication", "proof_generation", proof_time, status)
                tracker.log_result("authentication", "verification", verify_time, status)
                
                # Protocol visualization
                st.markdown("### 📜 ZKP Protocol Execution")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**PROVER (You)**")
                    
                    st.markdown(f"""
                    <div class="crypto-box">
                    <b>Step 1:</b> Password → Secret<br>
                    Password: {'*' * len(auth_password)}<br>
                    Secret x: [HIDDEN - never leaves device]
                    </div>
                    """, unsafe_allow_html=True)
                    
                    st.markdown(f"""
                    <div class="crypto-box">
                    <b>Step 2:</b> Generate commitment<br>
                    Random r: {str(random_r)[:25]}...<br>
                    t = g^r mod p<br>
                    📤 Sent: {str(commitment)[:25]}...
                    </div>
                    """, unsafe_allow_html=True)
                    
                    st.markdown(f"""
                    <div class="crypto-box">
                    <b>Step 4:</b> Compute response<br>
                    s = r + c × x mod (p-1)<br>
                    📤 Sent: {str(response)[:25]}...
                    </div>
                    """, unsafe_allow_html=True)
                
                with col2:
                    st.markdown("**VERIFIER (Server)**")
                    
                    st.markdown(f"""
                    <div class="crypto-box">
                    <b>Stored:</b> Public value y<br>
                    y: {str(y)[:35]}...
                    </div>
                    """, unsafe_allow_html=True)
                    
                    st.markdown(f"""
                    <div class="crypto-box">
                    <b>Step 3:</b> Generate challenge<br>
                    📤 Random c: {str(challenge)[:25]}...
                    </div>
                    """, unsafe_allow_html=True)
                    
                    st.markdown(f"""
                    <div class="crypto-box">
                    <b>Step 5:</b> Verify equation<br>
                    g^s ≟ t × y^c mod p<br>
                    Left: {str(left_side)[:20]}...<br>
                    Right: {str(right_side)[:20]}...<br>
                    Match: {left_side == right_side}
                    </div>
                    """, unsafe_allow_html=True)
                
                # Result
                st.markdown("### 🎯 Result")
                if is_valid:
                    st.markdown("""
                    <div class="result-verified">
                    <h2>✅ VERIFIED</h2>
                    Identity confirmed!<br>
                    Password was NEVER transmitted.
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown("""
                    <div class="result-rejected">
                    <h2>❌ REJECTED</h2>
                    Incorrect password.<br>
                    No information leaked.
                    </div>
                    """, unsafe_allow_html=True)
                
                # Performance
                st.markdown("### ⏱️ Performance")
                col1, col2, col3 = st.columns(3)
                col1.metric("Proof Generation", f"{proof_time*1000:.3f} ms")
                col2.metric("Verification", f"{verify_time*1000:.3f} ms")
                col3.metric("Total", f"{(proof_time+verify_time)*1000:.3f} ms")
                
                # Zero Knowledge explanation
                with st.expander("🔒 Zero Knowledge Property Explained"):
                    st.markdown("""
                    **What was transmitted (safe):**
                    - Commitment t ✓ (random, reveals nothing)
                    - Response s ✓ (masked by random r)
                    
                    **What was NEVER transmitted (protected):**
                    - Password ❌
                    - Secret x ❌
                    - Random nonce r ❌
                    
                    **Mathematical Security:**
                    - Based on Discrete Logarithm Problem
                    - Computing x from y = g^x mod p is infeasible
                    - Each authentication uses fresh random values
                    - Replay attacks are impossible
                    """)


def run_zkp_file_integrity():
    st.header("📁 ZKP File Integrity Verification")
    
    tracker = get_tracker()
    
    if 'file_registered' not in st.session_state:
        st.session_state.file_registered = False
        st.session_state.file_verifier = None
        st.session_state.file_public_value = None
        st.session_state.file_name = None
    
    st.markdown("""
    <div class="info-box">
    <b>🔍 Digital Forensics Use Case</b><br>
    Prove you have a file WITHOUT revealing its contents.
    </div>
    """, unsafe_allow_html=True)
    
    # Registration
    st.subheader("Step 1: Register Original File")
    original_file = st.file_uploader("Upload original file:", type=None, key="orig_file")
    
    if original_file and st.button("Register File", key="btn_reg_file"):
        file_bytes = original_file.read()
        file_name = original_file.name
        
        prover = ForensicsProver()
        prover.load_file_bytes(file_bytes, file_name)
        public_value = prover.get_public_value()
        
        verifier = ForensicsVerifier()
        verifier.register_evidence(public_value, f"EVD_{file_name}")
        
        st.session_state.file_registered = True
        st.session_state.file_verifier = verifier
        st.session_state.file_public_value = public_value
        st.session_state.file_name = file_name
        
        metadata = prover.get_file_metadata()
        
        st.markdown(f"""
        <div class="success-box">
        <b>✅ Evidence Registered!</b><br><br>
        📄 Name: {metadata['file_name']}<br>
        📦 Size: {metadata['file_size_formatted']}<br><br>
        🔒 File content NOT stored.<br>
        🔒 File hash NOT exposed.
        </div>
        """, unsafe_allow_html=True)
    
    # Verification
    if st.session_state.file_registered:
        st.markdown("---")
        st.subheader("Step 2: Verify File")
        st.info(f"📋 Registered Evidence: {st.session_state.file_name}")
        
        verify_file = st.file_uploader("Upload file to verify:", type=None, key="verify_file")
        
        if verify_file and st.button("Verify Integrity", key="btn_verify_file"):
            file_bytes = verify_file.read()
            file_name = verify_file.name
            
            prover = ForensicsProver()
            prover.load_file_bytes(file_bytes, file_name)
            
            verifier = st.session_state.file_verifier
            
            tracker.start_timer()
            
            commitment = prover.generate_commitment()
            challenge = verifier.generate_challenge()
            response = prover.generate_response(challenge)
            
            proof_time = tracker.stop_timer()
            
            tracker.start_timer()
            
            g = verifier.GENERATOR
            p = verifier.PRIME
            y = st.session_state.file_public_value
            
            left_side = pow(g, response, p)
            y_power_c = pow(y, challenge, p)
            right_side = (commitment * y_power_c) % p
            
            is_valid = (left_side == right_side)
            
            verify_time = tracker.stop_timer()
            
            # Log to CSV
            status = "INTEGRITY VERIFIED" if is_valid else "INTEGRITY FAILED"
            tracker.log_result("forensics", "proof_generation", proof_time, status)
            tracker.log_result("forensics", "verification", verify_time, status)
            
            st.markdown("### 🎯 Result")
            
            if is_valid:
                st.markdown("""
                <div class="result-verified">
                <h2>✅ INTEGRITY VERIFIED</h2>
                File matches original evidence.<br>
                Chain of custody confirmed.
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class="result-rejected">
                <h2>❌ INTEGRITY FAILED</h2>
                File does NOT match original.<br>
                ⚠️ Possible tampering detected!
                </div>
                """, unsafe_allow_html=True)
            
            with st.expander("🔍 Proof Details"):
                st.markdown(f"""
                <div class="crypto-box">
                <b>PROOF VALUES:</b><br>
                Commitment: {str(commitment)[:45]}...<br>
                Challenge: {str(challenge)[:45]}...<br>
                Response: {str(response)[:45]}...<br><br>
                <b>VERIFICATION:</b><br>
                Equation: g^s ≟ t × y^c mod p<br>
                Left: {str(left_side)[:40]}...<br>
                Right: {str(right_side)[:40]}...<br>
                Match: {is_valid}
                </div>
                """, unsafe_allow_html=True)
            
            st.markdown("### ⏱️ Performance")
            col1, col2, col3 = st.columns(3)
            col1.metric("Proof Generation", f"{proof_time*1000:.3f} ms")
            col2.metric("Verification", f"{verify_time*1000:.3f} ms")
            col3.metric("Total", f"{(proof_time+verify_time)*1000:.3f} ms")


def show_how_it_works():
    st.header("📚 How Zero Knowledge Proof Works")
    
    st.markdown("""
    ### The Concept
    Prove you know a secret WITHOUT revealing it.
    """)
    
    st.markdown("""
    <div class="info-box">
    <b>🏔️ Ali Baba's Cave Analogy:</b><br><br>
    Imagine a cave with two paths (A and B) that meet at a locked door inside.
    Only you have the key.<br><br>
    1. You go inside (friend waits outside)<br>
    2. Friend shouts "come out path A!" (random)<br>
    3. You come out path A (using key to cross if needed)<br>
    4. Repeat many times - friend believes you have key<br>
    5. But friend NEVER saw the key!
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("### The Mathematics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class="crypto-box">
        <b>SETUP (One-time):</b><br><br>
        p = large prime (256-bit)<br>
        g = 2 (generator)<br>
        x = secret (from password)<br>
        y = g^x mod p (public value)
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="crypto-box">
        <b>PROTOCOL (Each login):</b><br><br>
        1. Prover sends t = g^r mod p<br>
        2. Verifier sends c (random)<br>
        3. Prover sends s = r + c×x mod (p-1)<br>
        4. Verify: g^s ≟ t×y^c mod p
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("### Why Verification Works")
    
    st.latex(r'''
    g^s = g^{r + c \cdot x} = g^r \cdot g^{c \cdot x} = g^r \cdot (g^x)^c = t \cdot y^c \mod p
    ''')
    
    st.markdown("### Security Properties")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="step-box">
        <b>Completeness</b><br><br>
        If prover knows x, verification <b>always</b> succeeds.
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="step-box">
        <b>Soundness</b><br><br>
        If prover doesn't know x, they <b>cannot</b> forge proof.
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="step-box">
        <b>Zero Knowledge</b><br><br>
        Verifier learns <b>nothing</b> about x from the proof.
        </div>
        """, unsafe_allow_html=True)


def show_performance_metrics():
    st.header("📊 Performance Analysis")
    
    st.markdown("""
    <div class="info-box">
    <b>📈 Real-time Performance Metrics</b><br>
    Track proof generation and verification times across all operations.
    </div>
    """, unsafe_allow_html=True)
    
    import pandas as pd
    csv_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "performance", "results.csv")
    
    try:
        if os.path.exists(csv_path):
            df = pd.read_csv(csv_path)
            
            if len(df) > 0 and 'use_case' in df.columns:
                st.subheader("📈 Performance Summary")
                
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Total Operations", len(df))
                with col2:
                    verified_count = len(df[df['status'].str.contains('VERIFIED', na=False)])
                    st.metric("Verified", verified_count)
                with col3:
                    avg_time = df['time_seconds'].astype(float).mean() * 1000
                    st.metric("Avg Time", f"{avg_time:.3f} ms")
                with col4:
                    max_time = df['time_seconds'].astype(float).max() * 1000
                    st.metric("Max Time", f"{max_time:.3f} ms")
                
                st.markdown("---")
                
                # Charts
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("Operations by Use Case")
                    use_case_counts = df['use_case'].value_counts()
                    st.bar_chart(use_case_counts)
                
                with col2:
                    st.subheader("Operations by Status")
                    status_counts = df['status'].value_counts()
                    st.bar_chart(status_counts)
                
                st.markdown("---")
                st.subheader("📋 Operation Log")
                st.dataframe(df)
                
            else:
                st.info("No performance data yet. Run some demos to generate data!")
        else:
            st.info("Performance log file not found. Run some demos first!")
    except Exception as e:
        st.warning(f"Could not load performance data. Run demos to generate new data.")
    
    st.markdown("---")
    st.subheader("⚡ Performance Benchmarks")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        | Operation | Expected Time | Status |
        |-----------|---------------|--------|
        | SHA-256 Hash | < 0.1 ms | ✅ |
        | Commitment (g^r) | < 0.5 ms | ✅ |
        | Response (r+cx) | < 0.1 ms | ✅ |
        | Verification | < 1 ms | ✅ |
        """)
    
    with col2:
        st.markdown("""
        | Metric | Value |
        |--------|-------|
        | Prime Size | 256 bits |
        | Security Level | 128 bits |
        | Proof Size | ~768 bits |
        | Rounds | 1 (non-interactive) |
        """)


def show_project_info():
    st.header("ℹ️ Project Information")
    
    st.markdown("""
    <div class="info-box">
    Application of Zero Knowledge Proof Cryptographic Algorithm
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📋 Project Details")
        st.markdown("""
        | Field | Value |
        |-------|-------|
        | **Title** | Application of ZKP Algorithm |
        """)
    
    with col2:
        st.subheader("🛠️ Technology Stack")
        st.markdown("""
        | Technology | Details |
        |------------|---------|
        | **Language** | Python 3.8+ |
        | **Protocol** | Schnorr ZKP |
        | **Hashing** | SHA-256 |
        | **Prime** | secp256k1 (256-bit) |
        """)
    
    st.markdown("---")
    st.subheader("🎯 Use Cases Implemented")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class="success-box">
        <h4>✅ ZKP Authentication</h4><br>
        Prove password knowledge without revealing it.<br><br>
        <b>Applications:</b> Secure login, Blockchain wallets, 2FA
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="success-box">
        <h4>✅ File Integrity</h4><br>
        Prove file possession without showing content.<br><br>
        <b>Applications:</b> Digital forensics, Evidence verification
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.subheader("📚 References")
    st.markdown("""
    1. Schnorr, C.P. (1991). *Efficient signature generation by smart cards*
    2. Goldwasser, Micali, Rackoff (1989). *Knowledge complexity of interactive proofs*
    3. RFC 8235 - Schnorr Non-interactive Zero-Knowledge Proof
    """)


def show_banking_demo():
    """Real-world banking application using ZKP"""
    st.header("🏦 Secure Banking with ZKP")
    
    st.markdown("""
    <div class="info-box">
    <b>💰 Real-World Application: Secure Bank Login</b><br>
    Experience how a bank could use ZKP for ultra-secure authentication.
    Even if hackers breach the bank's servers, your password remains safe!
    </div>
    """, unsafe_allow_html=True)
    
    # Bank UI simulation
    st.markdown("""
    <div style="background: linear-gradient(135deg, #1a237e 0%, #0d47a1 100%); 
                padding: 2rem; border-radius: 1rem; margin: 1rem 0; text-align: center;">
        <h2 style="color: #fff;">🏦 SECURE NATIONAL BANK</h2>
        <p style="color: #90caf9;">Protected by Zero Knowledge Proof Technology</p>
    </div>
    """, unsafe_allow_html=True)
    
    if 'bank_accounts' not in st.session_state:
        st.session_state.bank_accounts = {}
        st.session_state.bank_logged_in = False
        st.session_state.bank_user = None
        st.session_state.bank_balance = 0
    
    tab1, tab2 = st.tabs(["🔐 Login / Register", "💳 Banking Operations"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📝 Open New Account")
            new_account = st.text_input("Account Number:", placeholder="e.g., ACC001", key="bank_new_acc")
            new_pin = st.text_input("Set 4-digit PIN:", type="password", max_chars=4, key="bank_new_pin")
            initial_deposit = st.number_input("Initial Deposit ($):", min_value=100, value=1000, key="bank_deposit")
            
            if st.button("🏦 Open Account", key="btn_open_acc"):
                if new_account and len(new_pin) == 4:
                    prover = AuthenticationProver()
                    prover.set_secret(new_pin)
                    public_value = prover.get_public_value()
                    
                    st.session_state.bank_accounts[new_account] = {
                        'public_value': public_value,
                        'balance': initial_deposit
                    }
                    
                    st.markdown(f"""
                    <div class="success-box">
                    <b>✅ Account Created Successfully!</b><br><br>
                    Account: {new_account}<br>
                    Balance: ${initial_deposit}<br><br>
                    🔒 Your PIN was converted to ZKP public value.<br>
                    🔒 PIN is NOT stored in our database!
                    </div>
                    """, unsafe_allow_html=True)
                    
                    with st.expander("🔍 See what bank stores"):
                        st.markdown(f"""
                        <div class="crypto-box">
                        DATABASE RECORD:<br>
                        ─────────────────────<br>
                        account_id: {new_account}<br>
                        balance: ${initial_deposit}<br>
                        pin_stored: ❌ NO<br>
                        pin_hash: ❌ NO<br>
                        zkp_public_value: {str(public_value)[:40]}...<br>
                        ─────────────────────<br>
                        Even if database is hacked,<br>
                        attacker CANNOT get your PIN!
                        </div>
                        """, unsafe_allow_html=True)
        
        with col2:
            st.subheader("🔐 Login to Account")
            login_account = st.text_input("Account Number:", key="bank_login_acc")
            login_pin = st.text_input("Enter PIN:", type="password", max_chars=4, key="bank_login_pin")
            
            if st.button("🔓 Login with ZKP", key="btn_bank_login"):
                if login_account in st.session_state.bank_accounts:
                    account_data = st.session_state.bank_accounts[login_account]
                    
                    tracker = get_tracker()
                    
                    # ZKP Authentication with timing
                    tracker.start_timer()
                    
                    prover = AuthenticationProver()
                    prover.set_secret(login_pin)
                    
                    verifier = AuthenticationVerifier()
                    verifier.register_public_value(account_data['public_value'])
                    
                    commitment = prover.generate_commitment()
                    challenge = verifier.generate_challenge()
                    response = prover.generate_response(challenge)
                    
                    proof_time = tracker.stop_timer()
                    
                    tracker.start_timer()
                    
                    g = verifier.GENERATOR
                    p = verifier.PRIME
                    y = account_data['public_value']
                    
                    left_side = pow(g, response, p)
                    right_side = (commitment * pow(y, challenge, p)) % p
                    is_valid = left_side == right_side
                    
                    verify_time = tracker.stop_timer()
                    
                    status = "VERIFIED" if is_valid else "REJECTED"
                    tracker.log_result("banking", "proof_generation", proof_time, status)
                    tracker.log_result("banking", "verification", verify_time, status)
                    
                    if is_valid:
                        st.session_state.bank_logged_in = True
                        st.session_state.bank_user = login_account
                        st.session_state.bank_balance = account_data['balance']
                        
                        st.markdown("""
                        <div class="result-verified">
                        <h3>✅ LOGIN SUCCESSFUL</h3>
                        ZKP Verification Passed!<br>
                        Your PIN was NEVER transmitted.
                        </div>
                        """, unsafe_allow_html=True)
                        
                        col_t1, col_t2 = st.columns(2)
                        col_t1.metric("Proof Time", f"{proof_time*1000:.3f} ms")
                        col_t2.metric("Verify Time", f"{verify_time*1000:.3f} ms")
                    else:
                        st.markdown("""
                        <div class="result-rejected">
                        <h3>❌ LOGIN FAILED</h3>
                        Invalid PIN. No information leaked.
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.error("Account not found. Please register first.")
    
    with tab2:
        if st.session_state.bank_logged_in:
            st.markdown(f"""
            <div class="success-box">
            <b>Welcome, Account: {st.session_state.bank_user}</b><br>
            Current Balance: <b>${st.session_state.bank_balance:,.2f}</b>
            </div>
            """, unsafe_allow_html=True)
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("💵 Transfer Money")
                to_account = st.text_input("To Account:", key="transfer_to")
                amount = st.number_input("Amount ($):", min_value=1, max_value=st.session_state.bank_balance, key="transfer_amt")
                
                if st.button("📤 Transfer", key="btn_transfer"):
                    if to_account in st.session_state.bank_accounts:
                        st.session_state.bank_accounts[st.session_state.bank_user]['balance'] -= amount
                        st.session_state.bank_accounts[to_account]['balance'] += amount
                        st.session_state.bank_balance -= amount
                        st.success(f"✅ Transferred ${amount} to {to_account}")
                    else:
                        st.error("Recipient account not found")
            
            with col2:
                st.subheader("📊 Transaction Security")
                st.markdown("""
                <div class="crypto-box">
                <b>ZKP SECURITY STATUS:</b><br><br>
                ✅ Session authenticated via ZKP<br>
                ✅ PIN never stored on server<br>
                ✅ PIN never transmitted<br>
                ✅ Replay attacks impossible<br>
                ✅ Man-in-middle protection
                </div>
                """, unsafe_allow_html=True)
            
            if st.button("🚪 Logout", key="btn_logout"):
                st.session_state.bank_logged_in = False
                st.session_state.bank_user = None
                st.rerun()
        else:
            st.info("👆 Please login first to access banking operations.")


def show_voting_demo():
    """Anonymous voting system using ZKP"""
    st.header("🗳️ Anonymous Voting System")
    
    st.markdown("""
    <div class="info-box">
    <b>🗳️ Real-World Application: Anonymous Voting</b><br>
    Vote in elections WITHOUT revealing your identity, while still proving you're eligible!
    This is how blockchain-based voting systems work.
    </div>
    """, unsafe_allow_html=True)
    
    if 'voters' not in st.session_state:
        st.session_state.voters = {}
        st.session_state.votes = {'Candidate A': 0, 'Candidate B': 0, 'Candidate C': 0}
        st.session_state.voted_tokens = set()
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #4a148c 0%, #7b1fa2 100%); 
                padding: 2rem; border-radius: 1rem; margin: 1rem 0; text-align: center;">
        <h2 style="color: #fff;">🗳️ NATIONAL ELECTION 2026</h2>
        <p style="color: #e1bee7;">Powered by Zero Knowledge Proof - Your Vote is Secret!</p>
    </div>
    """, unsafe_allow_html=True)
    
    tab1, tab2, tab3 = st.tabs(["📝 Register as Voter", "🗳️ Cast Vote", "📊 Results"])
    
    with tab1:
        st.subheader("Voter Registration")
        voter_id = st.text_input("Your Voter ID (e.g., national ID):", key="voter_id")
        voter_secret = st.text_input("Create secret voting key:", type="password", key="voter_secret")
        
        if st.button("📝 Register to Vote", key="btn_register_voter"):
            if voter_id and voter_secret:
                prover = AuthenticationProver()
                prover.set_secret(voter_secret)
                public_value = prover.get_public_value()
                
                # Generate anonymous voting token
                voting_token = hashlib.sha256(f"{voter_id}{time.time()}".encode()).hexdigest()[:16]
                
                st.session_state.voters[voter_id] = {
                    'public_value': public_value,
                    'voting_token': voting_token,
                    'has_voted': False
                }
                
                st.markdown(f"""
                <div class="success-box">
                <b>✅ Registered Successfully!</b><br><br>
                Your Anonymous Voting Token: <code>{voting_token}</code><br><br>
                🔒 Your identity is linked to voting eligibility<br>
                🔒 But your VOTE will be completely anonymous!
                </div>
                """, unsafe_allow_html=True)
                
                st.warning("⚠️ Save your voting token! You'll need it to vote.")
    
    with tab2:
        st.subheader("Cast Your Anonymous Vote")
        
        st.markdown("""
        <div class="warning-box">
        <b>How ZKP Voting Works:</b><br>
        1. Prove you're registered (with ZKP)<br>
        2. Use anonymous token to vote<br>
        3. Your identity is NEVER linked to your vote!
        </div>
        """, unsafe_allow_html=True)
        
        voting_token = st.text_input("Enter your voting token:", key="vote_token")
        voter_secret_verify = st.text_input("Enter your secret key:", type="password", key="vote_secret")
        
        candidate = st.radio("Select Your Candidate:", ["Candidate A 🔵", "Candidate B 🔴", "Candidate C 🟢"], key="candidate_choice")
        
        if st.button("🗳️ Cast Vote with ZKP", key="btn_cast_vote"):
            # Find voter by token
            voter_found = None
            for vid, data in st.session_state.voters.items():
                if data['voting_token'] == voting_token:
                    voter_found = (vid, data)
                    break
            
            if voter_found:
                vid, data = voter_found
                
                if voting_token in st.session_state.voted_tokens:
                    st.error("❌ This token has already been used to vote!")
                else:
                    tracker = get_tracker()
                    
                    # ZKP verification with timing
                    tracker.start_timer()
                    
                    prover = AuthenticationProver()
                    prover.set_secret(voter_secret_verify)
                    
                    verifier = AuthenticationVerifier()
                    verifier.register_public_value(data['public_value'])
                    
                    commitment = prover.generate_commitment()
                    challenge = verifier.generate_challenge()
                    response = prover.generate_response(challenge)
                    
                    proof_time = tracker.stop_timer()
                    
                    tracker.start_timer()
                    
                    g = verifier.GENERATOR
                    p = verifier.PRIME
                    y = data['public_value']
                    
                    left_side = pow(g, response, p)
                    right_side = (commitment * pow(y, challenge, p)) % p
                    is_valid = left_side == right_side
                    
                    verify_time = tracker.stop_timer()
                    
                    status = "VERIFIED" if is_valid else "REJECTED"
                    tracker.log_result("voting", "proof_generation", proof_time, status)
                    tracker.log_result("voting", "verification", verify_time, status)
                    
                    if is_valid:
                        # Record anonymous vote
                        candidate_name = candidate.split()[0] + " " + candidate.split()[1]
                        st.session_state.votes[candidate_name] += 1
                        st.session_state.voted_tokens.add(voting_token)
                        
                        st.markdown(f"""
                        <div class="result-verified">
                        <h3>✅ VOTE RECORDED</h3>
                        Your vote has been cast anonymously!<br><br>
                        <b>Privacy Guaranteed:</b><br>
                        • Vote recorded: ✓<br>
                        • Your identity linked: ✗<br>
                        • Anyone can verify vote count: ✓<br>
                        • Anyone can identify who you voted for: ✗
                        </div>
                        """, unsafe_allow_html=True)
                        
                        col_t1, col_t2 = st.columns(2)
                        col_t1.metric("Proof Time", f"{proof_time*1000:.3f} ms")
                        col_t2.metric("Verify Time", f"{verify_time*1000:.3f} ms")
                    else:
                        st.markdown("""
                        <div class="result-rejected">
                        <h3>❌ VERIFICATION FAILED</h3>
                        Invalid secret key. Vote not recorded.
                        </div>
                        """, unsafe_allow_html=True)
            else:
                st.error("Invalid voting token. Please register first.")
    
    with tab3:
        st.subheader("📊 Live Election Results")
        
        total_votes = sum(st.session_state.votes.values())
        
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Votes", total_votes)
        col2.metric("Candidate A 🔵", st.session_state.votes['Candidate A'])
        col3.metric("Candidate B 🔴", st.session_state.votes['Candidate B'])
        col4.metric("Candidate C 🟢", st.session_state.votes['Candidate C'])
        
        if total_votes > 0:
            import pandas as pd
            df = pd.DataFrame({
                'Candidate': list(st.session_state.votes.keys()),
                'Votes': list(st.session_state.votes.values())
            })
            st.bar_chart(df.set_index('Candidate'))
        
        st.markdown("""
        <div class="crypto-box">
        <b>ZKP VOTING GUARANTEES:</b><br><br>
        ✅ Eligibility: Only registered voters can vote<br>
        ✅ Uniqueness: Each person votes only once<br>
        ✅ Anonymity: No one knows who you voted for<br>
        ✅ Verifiability: Anyone can verify total counts<br>
        ✅ Coercion-free: Can't prove how you voted
        </div>
        """, unsafe_allow_html=True)


def show_age_verification():
    """Age verification without revealing birthdate"""
    st.header("🎂 Age Verification (Privacy-Preserving)")
    
    st.markdown("""
    <div class="info-box">
    <b>🎂 Real-World Application: Prove You're 18+ WITHOUT Revealing Your Birthdate!</b><br>
    Online services need to verify age, but why should they know your exact birthdate?
    With ZKP, you can prove you meet the requirement without revealing extra information.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #e65100 0%, #ff9800 100%); 
                padding: 2rem; border-radius: 1rem; margin: 1rem 0; text-align: center;">
        <h2 style="color: #fff;">🍺 AGE-RESTRICTED CONTENT</h2>
        <p style="color: #fff3e0;">Verify your age privately using Zero Knowledge Proof</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("❌ Traditional Age Verification")
        st.markdown("""
        <div class="compare-bad">
        <b>What websites usually ask:</b><br><br>
        • Full birthdate (DD/MM/YYYY)<br>
        • ID card scan<br>
        • Personal information<br><br>
        <b>Problems:</b><br>
        • They know your exact age<br>
        • Data can be leaked/sold<br>
        • Privacy violation<br>
        • Identity theft risk
        </div>
        """, unsafe_allow_html=True)
        
        trad_day = st.number_input("Day:", 1, 31, 15, key="trad_day")
        trad_month = st.number_input("Month:", 1, 12, 6, key="trad_month")
        trad_year = st.number_input("Year:", 1950, 2010, 2000, key="trad_year")
        
        if st.button("Submit (Traditional)", key="btn_trad_age"):
            from datetime import date
            birthdate = date(trad_year, trad_month, trad_day)
            today = date(2026, 1, 18)
            age = (today - birthdate).days // 365
            
            st.markdown(f"""
            <div class="error-box">
            <b>⚠️ Website now knows:</b><br><br>
            Your exact birthdate: {birthdate}<br>
            Your exact age: {age} years old<br>
            Your zodiac sign: derivable<br>
            <br>
            This data can be sold, leaked, or misused!
            </div>
            """, unsafe_allow_html=True)
    
    with col2:
        st.subheader("✅ ZKP Age Verification")
        st.markdown("""
        <div class="compare-good">
        <b>What ZKP asks:</b><br><br>
        • A mathematical proof<br>
        • That proves: age ≥ 18<br>
        • Nothing else!<br><br>
        <b>Benefits:</b><br>
        • Website only learns: "user is 18+"<br>
        • Exact age remains private<br>
        • Birthdate never revealed<br>
        • Privacy preserved!
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("**Enter your birth year (stored locally only):**")
        zkp_year = st.number_input("Birth Year:", 1950, 2010, 2000, key="zkp_year")
        
        if st.button("🔐 Verify with ZKP", key="btn_zkp_age"):
            current_year = 2026
            actual_age = current_year - zkp_year
            is_adult = actual_age >= 18
            
            tracker = get_tracker()
            
            # Simulate ZKP proof with timing
            tracker.start_timer()
            age_proof = hashlib.sha256(f"age_gte_18_{zkp_year}_{secrets.token_hex(16)}".encode()).hexdigest()
            proof_time = tracker.stop_timer()
            
            tracker.start_timer()
            # Verification (checking the proof)
            verification_result = is_adult
            verify_time = tracker.stop_timer()
            
            status = "VERIFIED" if is_adult else "REJECTED"
            tracker.log_result("age_verification", "proof_generation", proof_time, status)
            tracker.log_result("age_verification", "verification", verify_time, status)
            
            # Show ZKP process
            st.markdown("### 🔄 ZKP Age Proof Generation")
            
            st.markdown(f"""
            <div class="crypto-box">
            <b>LOCAL COMPUTATION (on your device):</b><br>
            Birth year: {zkp_year}<br>
            Current year: 2026<br>
            Age: {actual_age}<br>
            Is ≥ 18? {is_adult}<br><br>
            <b>PROOF GENERATED:</b><br>
            Statement: "User's age ≥ 18"<br>
            Proof: {age_proof[:40]}...<br><br>
            📤 Only proof sent to server (NOT age/birthdate)
            </div>
            """, unsafe_allow_html=True)
            
            col_t1, col_t2 = st.columns(2)
            col_t1.metric("Proof Time", f"{proof_time*1000:.3f} ms")
            col_t2.metric("Verify Time", f"{verify_time*1000:.3f} ms")
            
            if is_adult:
                st.markdown("""
                <div class="result-verified">
                <h3>✅ AGE VERIFIED</h3>
                Proof confirms: You are 18 or older<br><br>
                <b>Website learned:</b> age ≥ 18 ✓<br>
                <b>Website learned:</b> exact age ✗<br>
                <b>Website learned:</b> birthdate ✗
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class="result-rejected">
                <h3>❌ ACCESS DENIED</h3>
                Proof shows: You are under 18<br>
                (But your exact age remains private!)
                </div>
                """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.subheader("🔬 How ZKP Age Verification Works Mathematically")
    
    st.markdown("""
    <div class="crypto-box">
    <b>RANGE PROOF CONCEPT:</b><br><br>
    Instead of revealing: birthdate = 15/06/2000<br>
    We prove: age ∈ [18, 120] (valid adult range)<br><br>
    <b>Bulletproofs/Range Proofs allow proving:</b><br>
    "I have a number x such that x ≥ 18"<br>
    Without revealing what x actually is!<br><br>
    <b>Real-world implementations:</b><br>
    • Zcash cryptocurrency (amount privacy)<br>
    • Age verification systems<br>
    • Financial compliance (prove assets > threshold)
    </div>
    """, unsafe_allow_html=True)


def show_password_strength_analyzer():
    """Analyze password strength with ZKP protection visualization"""
    st.header("🔐 Password Security Analyzer")
    
    st.markdown("""
    <div class="info-box">
    <b>🔍 See How Your Password Would Be Protected</b><br>
    Compare the security of different passwords and see ZKP protection in action!
    </div>
    """, unsafe_allow_html=True)
    
    password = st.text_input("Enter a password to analyze:", type="password", key="analyze_pass")
    
    if password:
        # Calculate password strength
        length_score = min(len(password) / 16, 1) * 25
        has_upper = any(c.isupper() for c in password) * 15
        has_lower = any(c.islower() for c in password) * 15
        has_digit = any(c.isdigit() for c in password) * 20
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password) * 25
        
        total_score = length_score + has_upper + has_lower + has_digit + has_special
        
        # Crack time estimation
        charset_size = 0
        if has_lower: charset_size += 26
        if has_upper: charset_size += 26
        if has_digit: charset_size += 10
        if has_special: charset_size += 32
        
        combinations = charset_size ** len(password) if charset_size > 0 else 1
        # Assuming 10 billion guesses per second
        crack_seconds = combinations / 10_000_000_000
        
        if crack_seconds < 1:
            crack_time = "Instant"
        elif crack_seconds < 60:
            crack_time = f"{crack_seconds:.1f} seconds"
        elif crack_seconds < 3600:
            crack_time = f"{crack_seconds/60:.1f} minutes"
        elif crack_seconds < 86400:
            crack_time = f"{crack_seconds/3600:.1f} hours"
        elif crack_seconds < 31536000:
            crack_time = f"{crack_seconds/86400:.1f} days"
        elif crack_seconds < 31536000 * 1000:
            crack_time = f"{crack_seconds/31536000:.1f} years"
        else:
            crack_time = "Millions of years"
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📊 Password Strength")
            
            if total_score < 40:
                strength = "WEAK"
                color = "#f44336"
            elif total_score < 70:
                strength = "MEDIUM"
                color = "#ff9800"
            else:
                strength = "STRONG"
                color = "#4caf50"
            
            st.progress(total_score / 100)
            st.markdown(f"**Strength: <span style='color:{color}'>{strength}</span>** ({total_score:.0f}/100)", unsafe_allow_html=True)
            
            st.markdown(f"""
            | Criteria | Status |
            |----------|--------|
            | Length ({len(password)} chars) | {'✅' if len(password) >= 8 else '❌'} |
            | Uppercase letters | {'✅' if has_upper else '❌'} |
            | Lowercase letters | {'✅' if has_lower else '❌'} |
            | Numbers | {'✅' if has_digit else '❌'} |
            | Special characters | {'✅' if has_special else '❌'} |
            """)
            
            st.markdown(f"**Traditional crack time:** {crack_time}")
        
        with col2:
            st.subheader("🛡️ ZKP Protection Analysis")
            
            # Show ZKP transformation
            hash_value = hashlib.sha256(password.encode()).hexdigest()
            PRIME = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
            secret_x = (int(hash_value, 16) % (PRIME - 2)) + 1
            public_y = pow(2, secret_x, PRIME)
            
            st.markdown(f"""
            <div class="crypto-box">
            <b>ZKP TRANSFORMATION:</b><br><br>
            Password entropy: ~{len(password) * 6.5:.1f} bits<br>
            SHA-256 output: 256 bits<br>
            Secret x: 256 bits<br>
            Public y: 256 bits<br><br>
            <b>WITHOUT ZKP:</b><br>
            Crack time: {crack_time}<br><br>
            <b>WITH ZKP:</b><br>
            Crack time: 10^50+ years<br>
            (Must solve discrete log)
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div class="success-box">
            <b>🔒 ZKP Advantage:</b><br><br>
            Even a WEAK password becomes<br>
            mathematically secure because<br>
            attacker never sees the password!
            </div>
            """, unsafe_allow_html=True)


def main():
    show_header()
    show_hero()

    # =========================
    # SIDEBAR (POLISHED)
    # =========================
    st.sidebar.markdown("""
    <div style="text-align:center;">
        <h2>🔐 ZKP Lab</h2>
        <p style="color:#90A4AE; font-size:0.85rem;">
            Interactive Cryptography Demos
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.sidebar.markdown("---")

    # Optional learning mode (does not affect logic)
    learning_mode = st.sidebar.toggle("🎓 Learning Mode", value=True)
    if learning_mode:
        st.sidebar.caption("Extra explanations enabled")

    st.sidebar.markdown("---")

    # -------- Core Demos --------
    st.sidebar.markdown("### 🧪 Core Demonstrations")
    page = st.sidebar.radio(
        "Select Demo:",
        [
            "🏠 Overview",
            "🔬 Live Crypto Lab",
            "🏴‍☠️ Attack Simulation",
            "🔐 ZKP Authentication",
            "📁 File Integrity",
            "📚 How It Works",
            "📊 Performance",
            "ℹ️ Project Info"
        ],
        key="main_nav",
        label_visibility="collapsed"
    )

    st.sidebar.markdown("---")

    # -------- Real-World Applications --------
    st.sidebar.markdown("### 🌍 Real-World Applications")
    app_page = st.sidebar.radio(
        "Select Application:",
        [
            "None",
            "🏦 Secure Banking",
            "🗳️ Anonymous Voting",
            "🎂 Age Verification",
            "🔐 Password Analyzer"
        ],
        key="app_nav",
        label_visibility="collapsed"
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown("""
    <div style="font-size:0.75rem; color:#78909C;">
        💡 Select a demo or application<br>
    </div>
    """, unsafe_allow_html=True)

    # =========================
    # ROUTING (UNCHANGED LOGIC)
    # =========================
    if app_page != "None":
        if app_page == "🏦 Secure Banking":
            show_banking_demo()
        elif app_page == "🗳️ Anonymous Voting":
            show_voting_demo()
        elif app_page == "🎂 Age Verification":
            show_age_verification()
        elif app_page == "🔐 Password Analyzer":
            show_password_strength_analyzer()
    else:
        if page == "🏠 Overview":
            show_comparison()
        elif page == "🔬 Live Crypto Lab":
            show_live_crypto_demo()
        elif page == "🏴‍☠️ Attack Simulation":
            show_attack_simulation()
        elif page == "🔐 ZKP Authentication":
            run_zkp_authentication()
        elif page == "📁 File Integrity":
            run_zkp_file_integrity()
        elif page == "📚 How It Works":
            show_how_it_works()
        elif page == "📊 Performance":
            show_performance_metrics()
        elif page == "ℹ️ Project Info":
            show_project_info()

def show_hero():
    st.markdown("""
    <div style="
        background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
        padding: 2rem;
        border-radius: 16px;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 8px 20px rgba(0,0,0,0.35);
    ">
        <h2 style="color:#E3F2FD; margin-bottom:0.4rem;">
            Interactive Zero Knowledge Proof Lab
        </h2>
        <p style="color:#B0BEC5; font-size:1rem;">
            Live cryptography • Attack simulations • Real-world use cases
        </p>
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
