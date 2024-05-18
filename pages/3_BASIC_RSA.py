import streamlit as st

# RSA Algorithm functions
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def e_value(phi_n):
    e = 2
    while e < phi_n:
        if gcd(e, phi_n) == 1:
            return e
        e += 1
    raise ValueError("Failed to find an appropriate e value.")

def d_value(e, phi_n):
    d, k = 1, 1
    while True:
        d = (1 + k * phi_n) // e
        if (d * e) % phi_n == 1:
            return d
        k += 1

def is_prime(num):
    if num <= 1:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True

def generate_keypair(p, q):
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = e_value(phi_n)
    d = d_value(e, phi_n)
    return (e, n), (d, n)

def string_to_int(message):
    return [ord(char) for char in message]

def int_to_string(numbers):
    return ''.join(chr(number) for number in numbers)

def encrypt(message, public_key):
    e, n = public_key
    message_int = string_to_int(message)
    encrypted_int = [(char ** e) % n for char in message_int]
    return encrypted_int

def decrypt(ciphertext, private_key):
    d, n = private_key
    decrypted_int = [(char ** d) % n for char in ciphertext]
    return int_to_string(decrypted_int)

# Initialize Streamlit app
st.title("RSA Cipher")

st.markdown(
    """
**RSA Cipher: A Cornerstone of Public-Key Cryptography**

The RSA cipher is a widely used cryptographic algorithm that enables secure data transmission over insecure networks. It is a public-key cryptosystem, meaning it uses two keys: a public key for encryption and a private key for decryption. The security of RSA hinges on the difficulty of factoring large composite numbers.

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

# User input for prime numbers
p = st.number_input("Enter a prime number (p):", min_value=2, step=1)
q = st.number_input("Enter a prime number (q):", min_value=2, step=1)

# Generate key pair
if st.button("Generate Key Pair"):
    if not (p != q and is_prime(p) and is_prime(q)):
        st.error("Please enter two different prime numbers.")
    else:
        public_key, private_key = generate_keypair(p, q)
        st.session_state.public_key = public_key
        st.session_state.private_key = private_key
        st.session_state.key_generated = True
        st.success("Key pair generated successfully!")

# Display the generated keys if they exist in the session state
if 'public_key' in st.session_state and 'private_key' in st.session_state:
    st.write("Public Key (e, n):", st.session_state.public_key)
    st.write("Private Key (d, n):", st.session_state.private_key)

# Encrypt Messages
message = st.text_input("Enter a message to encrypt:")

if st.button("Encrypt"):
    if st.session_state.get('key_generated', False):
        encrypted_message = encrypt(message, st.session_state.public_key)
        encrypted_message_str = ", ".join([str(val) for val in encrypted_message])
        st.session_state.encrypted_message = encrypted_message
        st.write("Encrypted Text:")
        st.text(f"[{encrypted_message_str}]")
    else:
        st.error("Please generate a key pair first.")

# Decrypt Messages
private_key_input = st.text_input("Enter the private key to decrypt the message (format: d,n)")

if st.button("Decrypt"):
    if st.session_state.get('key_generated', False):
        try:
            private_key_parts = private_key_input.split(",")
            private_key_d = int(private_key_parts[0])
            private_key_n = int(private_key_parts[1])
            private_key = (private_key_d, private_key_n)

            if private_key == st.session_state.private_key:
                ciphertext = st.session_state.encrypted_message
                decrypted_message = decrypt(ciphertext, private_key)
                st.write("Decrypted Message:", decrypted_message)
            else:
                st.error("Invalid private key!")
        except ValueError:
            st.error("Please enter valid integer values for the private key.")
    else:
        st.error("Please generate a key pair first.")
