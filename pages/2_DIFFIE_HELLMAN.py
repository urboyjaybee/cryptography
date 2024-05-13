import streamlit as st
import random

def is_prime(n):
    """Check if a number is prime."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def modexp(base, exponent, modulus):
    """Modular exponentiation."""
    result = 1
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def generate_primes(min_val, max_val):
    """Generate two distinct prime numbers within the given range."""
    primes = []
    for num in range(min_val, max_val + 1):
        if is_prime(num):
            primes.append(num)
    return random.sample(primes, 2)

def diffie_hellman(p, g, a, b):
    """Perform the Diffie-Hellman key exchange."""
    A = modexp(g, a, p)
    B = modexp(g, b, p)
    secret_key_A = modexp(B, a, p)
    secret_key_B = modexp(A, b, p)
    return secret_key_A, secret_key_B

st.title("Diffie-Hellman Key Exchange")

# Generate random prime numbers p and g
p, g = generate_primes(100, 1000)

st.write(f"Prime number (p): {p}")
st.write(f"Primitive root (g): {g}")

# Alice's private key
a = st.number_input("Alice's Private Key (a):", min_value=1, max_value=p-1, key="alice")

# Bob's private key
b = st.number_input("Bob's Private Key (b):", min_value=1, max_value=p-1, key="bob")

if st.button("Perform Key Exchange"):
    if not (is_prime(p) and modexp(g, p-1, p) == 1 and a < p and b < p):
        st.error("Invalid input. Please make sure 'p' is prime, 'g' is a primitive root modulo 'p', and 'a' and 'b' are less than 'p'.")
    else:
        secret_key_A, secret_key_B = diffie_hellman(p, g, a, b)
        st.success("Key exchange successful!")
        st.write(f"Alice's Secret Key: {secret_key_A}")
        st.write(f"Bob's Secret Key: {secret_key_B}")
