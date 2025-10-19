# filename: password_strength_lab.py
import streamlit as st
import bcrypt
from argon2 import PasswordHasher
import hashlib
import math

# -----------------------
# Helper functions
# -----------------------
def hash_password(password, algo="bcrypt", rounds=12):
    if algo == "bcrypt":
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds))
        return hashed.decode()
    elif algo == "argon2":
        ph = PasswordHasher(time_cost=2, memory_cost=1024*rounds, parallelism=2)
        return ph.hash(password)
    elif algo == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()

def calculate_entropy(password):
    """Estimate entropy in bits based on character set."""
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(not c.isalnum() for c in password):
        charset_size += 32  # common special characters
    entropy = len(password) * math.log2(charset_size) if charset_size else 0
    return round(entropy, 2)

def estimate_crack_time(entropy_bits, algo="bcrypt", rounds=12, attacker="CPU"):
    """Estimate time to brute-force based on entropy and hash cost."""
    speeds = {"CPU": 1e9, "GPU": 1e12, "Quantum": 1e15}  # guesses/sec

    # Cost factor multiplier for hashing algorithm
    if algo == "bcrypt":
        cost_multiplier = 2 ** rounds
    elif algo == "argon2":
        cost_multiplier = rounds * 50
    else:  # sha256
        cost_multiplier = 1

    total_combinations = 2 ** entropy_bits
    time_sec = total_combinations * cost_multiplier / speeds[attacker]
    return time_sec

def format_time(seconds):
    """Convert seconds into readable format."""
    units = [("years", 365*24*3600), ("days", 24*3600), ("hours",3600), ("minutes",60), ("seconds",1)]
    result = []
    for name, count in units:
        val = int(seconds // count)
        if val > 0:
            result.append(f"{val} {name}")
            seconds %= count
    return ", ".join(result) if result else "less than 1 second"

def strength_percentage(entropy_bits, max_entropy=128):
    pct = min(entropy_bits / max_entropy * 100, 100)
    return int(pct)

# -----------------------
# Streamlit GUI
# -----------------------
st.title("🔐 Password Strength Lab (Interactive)")

password = st.text_input("Enter your password", type="password")
algo = st.selectbox("Hash Algorithm", ["bcrypt", "argon2", "sha256"])
rounds = st.slider("Hash cost parameter (rounds/memory)", 1, 20, 12)

if password:
    # 1. Entropy & strength
    entropy = calculate_entropy(password)
    st.metric("Estimated Entropy (bits)", entropy)
    strength_pct = strength_percentage(entropy)
    st.progress(strength_pct)
    if strength_pct < 30:
        st.warning("Weak password")
    elif strength_pct < 60:
        st.info("Moderate password")
    else:
        st.success("Strong password")

    # 2. Hashing
    hashed_pw = hash_password(password, algo=algo, rounds=rounds)
    st.subheader("Hashed Password:")
    st.code(hashed_pw)

    # 3. Crack time estimates
    st.subheader("Estimated Crack Times (Simulated):")
    crack_times = {}
    for atk in ["CPU", "GPU", "Quantum"]:
        sec = estimate_crack_time(entropy, algo=algo, rounds=rounds, attacker=atk)
        formatted = format_time(sec)
        crack_times[atk] = formatted
        st.write(f"{atk}: {formatted}")
