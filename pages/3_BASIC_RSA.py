import streamlit as st

public_key = None
private_key = None
key_generated = False

def generate_keypair(p, q):
    global public_key, private_key, key_generated
    n = p * q
    t = (p - 1) * (q - 1)
    e = find_public_key(t)
    d = find_private_key(e, t)
    public_key = (n, e)
    private_key = (n, d)
    key_generated = False  # Update key_generated to True after successful key generation

def find_public_key(t):
    e = 2
    while True:
        if gcd(e, t) == 1:
            return e
        e += 1

def find_private_key(e, t):
    d = 2
    while True:
        if (d * e) % t == 1:
            return d
        d += 1

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def is_prime(n):
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

def encrypt(message, public_key):
    n, e = public_key
    return (message ** e) % n

def decrypt(ciphertext, private_key):
    n, d = private_key
    return (ciphertext ** d) % n

st.title("RSA Cipher")
st.markdown(
    """
**RSA Cipher: A Cornerstone of Public-Key Cryptography**

The RSA cipher is a widely used cryptographic algorithm that enables secure data transmission over insecure networks. It is a public-key cryptosystem, meaning it uses two keys: a public key for encryption and a private key for decryption. The security of RSA hinges on the difficulty of factoring large composite numbers.

**History**

* Developed in 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman (RSA).
* An equivalent system was independently developed earlier (1973) by Clifford Cocks at GCHQ, a British intelligence agency, but remained classified until 1997.

**Pseudocode Process**

1. **Key Generation**
   * Choose two distinct prime numbers, p and q.
   * Calculate n = p * q.
   * Calculate Euler's totient function: φ(n) = (p - 1) * (q - 1).
   * Choose an integer e, such that 1 < e < φ(n) and gcd(e, φ(n)) = 1.
   * Calculate d as the modular multiplicative inverse of e modulo φ(n).
   * Public key: (e, n)
   * Private key: (d, n)

2. **Encryption**
   * Given a message M (represented as an integer), calculate the ciphertext C:
     * C = M^e mod n

3. **Decryption**
   * Given the ciphertext C, calculate the original message M:
     * M = C^d mod n

**Important Note:** The strength of RSA lies in choosing large prime numbers (p and q) to create a large modulus (n). Larger keys make it computationally infeasible to factor n and determine the private key (d).
"""
)

p = st.number_input("Enter a prime number (p):", min_value=2, step=1)
q = st.number_input("Enter a prime number (q):", min_value=2, step=1)

if st.button("Generate Key Pair"):
    if not (p != q and is_prime(p) and is_prime(q)):
        st.error("Please enter two different prime numbers.")
    else:
        generate_keypair(p, q)
        st.success("Key pair generated successfully!")
        st.write("Public Key (e, n):", public_key)
        st.write("Private Key (d, n):", private_key)

message = st.text_input("Enter a message to encrypt/decrypt:")
action = st.radio("Select Action:", ["Encrypt", "Decrypt"])

if action == "Encrypt":
    if st.button("Encrypt"):
        if key_generated:
            encrypted_message = encrypt(int(message), public_key)
            st.write("Encrypted Message:", encrypted_message)
        else:
            st.error("Please generate a key pair first.")

if action == "Decrypt":
    if st.button("Decrypt"):
        if key_generated:
            decrypted_message = decrypt(int(message), private_key)
            st.write("Decrypted Message:", decrypted_message)
        else:
            st.error("Please generate a key pair first.")
