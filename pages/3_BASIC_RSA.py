import streamlit as st

def generate_keypair(p, q):
    n = p * q
    t = (p - 1) * (q - 1)
    e = find_public_key(t)
    d = find_private_key(e, t)
    return (n, e), (n, d)

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

def encrypt(message, public_key):
    n, e = public_key
    return (message ** e) % n

def decrypt(ciphertext, private_key):
    n, d = private_key
    return (ciphertext ** d) % n

st.title("RSA Cipher")

p = st.number_input("Enter a prime number (p):", min_value=2, step=1)
q = st.number_input("Enter a prime number (q):", min_value=2, step=1)

if st.button("Generate Key Pair"):
    if not (p != q and is_prime(p) and is_prime(q)):
        st.error("Please enter two different prime numbers.")
    else:
        public_key, private_key = generate_keypair(p, q)
        st.success("Key pair generated successfully!")
        st.write("Public Key (e, n):", public_key)
        st.write("Private Key (d, n):", private_key)

message = st.text_input("Enter a message to encrypt/decrypt:")
action = st.radio("Select Action:", ["Encrypt", "Decrypt"])

if action == "Encrypt":
    if st.button("Encrypt"):
        if public_key:
            encrypted_message = encrypt(int(message), public_key)
            st.write("Encrypted Message:", encrypted_message)
        else:
            st.error("Please generate a key pair first.")

if action == "Decrypt":
    if st.button("Decrypt"):
        if private_key:
            decrypted_message = decrypt(int(message), private_key)
            st.write("Decrypted Message:", decrypted_message)
        else:
            st.error("Please generate a key pair first.")

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
