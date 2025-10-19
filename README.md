## password-strength-lab
# Password Strength Lab (Interactive)
Password Strength Lab is an educational, interactive simulator that helps users understand password entropy, how hashing choices (bcrypt, Argon2, SHA‑256) and salt/cost parameters affect brute‑force cracking time, and how different attacker models (CPU, GPU, and a simulated quantum attacker) compare.
This tool is for learning and demonstration only. It does not perform real attacks and should never be used against real accounts or systems.
# Features
Interactive web UI (Streamlit) to enter a password and tune hashing parameters.
Shows estimated entropy (bits) and a strength percentage.
Computes simulated time-to-crack for different attacker models:
CPU (classical)
GPU (parallel hardware
Quantum (simulated — see note on Grover)
Hashes the password using bcrypt, Argon2, or SHA‑256 (for demonstration).
Visual strength meter and readable crack-time outputs.
Clear explanation of the math and assumptions used by the simulator.
# Quick demo (what you’ll see)
Enter password → see entropy in bits and a progress bar percentage.
Select hashing algorithm and cost (rounds / memory).
See hashed output (bcrypt/Argon2) and an estimate of how long a CPU, GPU, or quantum adversary would take to brute-force the password (simulated).
Option to adjust attacker speeds and hashing parameters to explore trade-offs.
Getting started
Requirements
Python 3.8+
# Recommended packages:
streamlit
bcrypt
argon2-cffi
matplotlib (optional, for plotting)
# Install dependencies with pip:
pip install streamlit bcrypt argon2-cffi matplotlib
# Run the app
streamlit run password_strength_lab.py
The app will open in your default browser at http://localhost:8501.

