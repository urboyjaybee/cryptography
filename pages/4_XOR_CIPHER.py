import streamlit as st
from io import BytesIO

def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key."""
    ciphertext = bytearray()
    for i in range(len(plaintext)):
        input_text_byte = plaintext[i]
        key_byte = key[i % len(key)]
        encrypted_byte = input_text_byte ^ key_byte
        ciphertext.append(encrypted_byte)
    return ciphertext

def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    return xor_encrypt(ciphertext, key)  # XOR decryption is the same as encryption

def encrypt_text(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key."""
    plaintext_bytes = plaintext.encode()
    encrypted_bytes = xor_encrypt(plaintext_bytes, key.encode())
    return encrypted_bytes.hex()

def decrypt_text(ciphertext_hex, key):
    """Decrypts ciphertext (in hexadecimal format) using XOR cipher with the given key."""
    try:
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)
        decrypted_bytes = xor_decrypt(ciphertext_bytes, key.encode())
        return decrypted_bytes.decode()
    except ValueError:
        return None

def encrypt_file(file_content, key):
    """Encrypts file content using XOR cipher with the given key."""
    encrypted_bytes = xor_encrypt(file_content, key.encode())
    return encrypted_bytes

def decrypt_file(file_content, key):
    """Decrypts file content using XOR cipher with the given key."""
    decrypted_bytes = xor_decrypt(file_content, key.encode())
    return decrypted_bytes

st.header("XOR Cipher - Text and File Encryption")
st.markdown(
    """
**XOR Cipher: Simple Yet Effective Symmetric Encryption**

The XOR (exclusive OR) cipher is a type of symmetric encryption that operates on binary data. It takes two inputs (plaintext and key) and produces a ciphertext by applying the XOR operation to each corresponding bit. The same key is used for both encryption and decryption.

**History**
- One of the earliest and simplest ciphers.
- Widely used in the early days of computing due to its ease of implementation.
- Although not secure on its own due to its linearity, it's often used as a component within more complex encryption schemes.

**Pseudocode Process**
1. **Encryption**
   - For each bit in the plaintext:
     - Combine it with the corresponding bit in the key using the XOR operation:
       - 0 XOR 0 = 0
       - 0 XOR 1 = 1
       - 1 XOR 0 = 1
       - 1 XOR 1 = 0
     - The result of each XOR operation forms a bit in the ciphertext.
2. **Decryption**
   - Identical to encryption. Applying the same XOR operation with the key to the ciphertext recovers the original plaintext.

**Example:**
Plaintext:  01101001
Key:        10101010
Ciphertext: 11000011

**Important Note:** The security of the XOR cipher relies heavily on the secrecy and randomness of the key. If the key is reused or predictable, the cipher becomes vulnerable to attack.
"""
)

# Choose between Text or File Encryption/Decryption
option = st.radio("Select Mode:", ("Encrypt Text", "Decrypt Text", "Encrypt File", "Decrypt File"))

if option == "Encrypt Text":
    plaintext = st.text_area("Plain Text:")
    key = st.text_input("Key:")
    if st.button("Encrypt"):
        if not plaintext or not key:
            st.warning("Please enter both plaintext and key.")
        else:
            encrypted_text_hex = encrypt_text(plaintext, key)
            st.write("Ciphertext (Hex):", encrypted_text_hex)

elif option == "Decrypt Text":
    ciphertext_hex = st.text_area("Ciphertext (Hex):")
    key = st.text_input("Key:")
    if st.button("Decrypt"):
        if not ciphertext_hex or not key:
            st.warning("Please enter both ciphertext (in Hex) and key.")
        else:
            decrypted_text = decrypt_text(ciphertext_hex, key)
            if decrypted_text:
                st.write("Decrypted Text:", decrypted_text)
            else:
                st.error("Invalid ciphertext or key.")

elif option == "Encrypt File":
    uploaded_file = st.file_uploader("Choose a file for encryption:")
    key = st.text_input("Key:")
    if st.button("Encrypt File"):
        if not uploaded_file or not key:
            st.warning("Please upload a file and enter a key for encryption.")
        else:
            file_content = uploaded_file.read()
            encrypted_content = encrypt_file(file_content, key)
            encrypted_file = BytesIO(encrypted_content)
            encrypted_file.name = f"encrypted_{uploaded_file.name}"
            st.download_button(label="Download Encrypted File", data=encrypted_file, file_name=encrypted_file.name)

elif option == "Decrypt File":
    uploaded_encrypted_file = st.file_uploader("Choose a file for decryption:")
    key = st.text_input("Key:")
    if st.button("Decrypt File"):
        if not uploaded_encrypted_file or not key:
            st.warning("Please upload an encrypted file and enter a key for decryption.")
        else:
            file_content = uploaded_encrypted_file.read()
            decrypted_content = decrypt_file(file_content, key)
            decrypted_file = BytesIO(decrypted_content)
            decrypted_file.name = f"decrypted_{uploaded_encrypted_file.name}"
            st.download_button(label="Download Decrypted File", data=decrypted_file, file_name=decrypted_file.name)
