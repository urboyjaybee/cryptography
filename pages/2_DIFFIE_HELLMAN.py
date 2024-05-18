import streamlit as st
import random
from sympy import isprime, primerange, primitive_root

def modexp(base, exponent, modulus):
    """Modular exponentiation."""
    result = 1
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def generate_prime_and_primitive_root(min_val, max_val):
    """Generate a prime number and its primitive root within the given range."""
    primes = list(primerange(min_val, max_val))
    prime = random.choice(primes)
    prim_root = primitive_root(prime)
    return prime, prim_root

def diffie_hellman(p, g, a, b):
    """Perform the Diffie-Hellman key exchange."""
    A = modexp(g, a, p)
    B = modexp(g, b, p)
    secret_key_A = modexp(B, a, p)
    secret_key_B = modexp(A, b, p)
    return secret_key_A, secret_key_B

st.title("Diffie-Hellman Key Exchange")

st.markdown(
    """
    **Diffie-Hellman Key Exchange**

    The Diffie-Hellman key exchange is a method for securely exchanging cryptographic keys over a public channel. 
    It allows two parties to agree upon a shared secret key without revealing the key to any eavesdropper.

    **Algorithm Overview:**

    1. **Key Generation:**
       - Choose a large prime number \( p \) and a primitive root \( g \) modulo \( p \).
    
    2. **Private Key Generation:**
       - Alice chooses a secret integer \( a \) (her private key).
       - Bob chooses a secret integer \( b \) (his private key).

    3. **Public Key Exchange:**
       - Alice computes \( A = g^a \mod p \) (her public key).
       - Bob computes \( B = g^b \mod p \) (his public key).

    4. **Secret Key Computation:**
       - Alice computes the secret key \( K = B^a \mod p \).
       - Bob computes the secret key \( K = A^b \mod p \).

    **Security Note:**
    The security of the Diffie-Hellman key exchange relies on the discrete logarithm problem, which is difficult to solve efficiently.

    **Input Requirements:**
    - \( p \) must be a prime number.
    - \( g \) must be a primitive root modulo \( p \).
    - \( a \) and \( b \) must be integers less than \( p \).

    """
)

# Generate random prime numbers p and g
p, g = generate_prime_and_primitive_root(100, 1000)

st.write(f"Prime number (p): {p}")
st.write(f"Primitive root (g): {g}")

# Alice's private key
a = st.number_input("Alice's Private Key (a):", min_value=1, max_value=p-1, key="alice")

# Bob's private key
b = st.number_input("Bob's Private Key (b):", min_value=1, max_value=p-1, key="bob")

if st.button("Perform Key Exchange"):
    if not (isprime(p) and modexp(g, p-1, p) == 1 and a < p and b < p):
        st.error("Invalid input. Please make sure 'p' is prime, 'g' is a primitive root modulo 'p', and 'a' and 'b' are less than 'p'.")
    else:
        secret_key_A, secret_key_B = diffie_hellman(p, g, a, b)
        st.success("Key exchange successful!")
        st.write(f"Alice's Secret Key: {secret_key_A}")
        st.write(f"Bob's Secret Key: {secret_key_B}")
