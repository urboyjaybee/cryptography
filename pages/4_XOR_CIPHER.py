import streamlit as st

st.header("XOR Cipher")
st.markdown(
    """
**XOR Cipher: Simple Yet Effective Symmetric Encryption**

The XOR (exclusive OR) cipher is a type of symmetric encryption that operates on binary data. It takes two inputs (plaintext and key) and produces a ciphertext by applying the XOR operation to each corresponding bit.  The same key is used for both encryption and decryption.

**History**

* One of the earliest and simplest ciphers.
* Widely used in the early days of computing due to its ease of implementation.
* Although not secure on its own due to its linearity, it's often used as a component within more complex encryption schemes.

**Pseudocode Process**

1. **Encryption**
   * For each bit in the plaintext:
      * Combine it with the corresponding bit in the key using the XOR operation:
        * 0 XOR 0 = 0
        * 0 XOR 1 = 1
        * 1 XOR 0 = 1
        * 1 XOR 1 = 0
      * The result of each XOR operation forms a bit in the ciphertext.

2. **Decryption**
   * Identical to encryption. Applying the same XOR operation with the key to the ciphertext recovers the original plaintext.

**Example:**
Plaintext:  01101001
Key:        10101010
Ciphertext: 11000011

**Important Note:** The security of the XOR cipher relies heavily on the secrecy and randomness of the key. If the key is reused or predictable, the cipher becomes vulnerable to attack.
"""
)

plaintext = bytes(st.text_area("Plain Text:").encode())

key = bytes(st.text_input("Key:").encode())

def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key, st.writeing bits involved."""

    ciphertext = bytearray()
    for i in range(len(plaintext)):
        input_text_byte = plaintext[i]
        key_byte =  key[i % len(key)]
        encrypted_byte = input_text_byte ^ key_byte
        ciphertext.append(encrypted_byte)
        st.write(f"plaintext byte: {format(input_text_byte, '08b')} = {chr(input_text_byte)}")
        st.write(f"Key byte:       {format(key_byte, '08b')} = {chr(key_byte)}")
        st.write(f"XOR result:     {format(encrypted_byte, '08b')} = {chr(encrypted_byte)}")
        
        st.write("--------------------")
    return ciphertext


def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    return xor_encrypt(ciphertext, key)   # XOR decryption is the same as encryption



if st.button("Submit"):
    if plaintext.decode() == key.decode():
        st.write("plaintext should not be equal to the key")
    
    elif len(key.decode()) > len(plaintext.decode()):
        st.write("plaintext length should be equal or greater than the length of key")
    else:
        encrypted_text = xor_encrypt(plaintext, key)
        st.write("Ciphertext:", encrypted_text.decode())
        decrypted_text = xor_decrypt(encrypted_text, key)
        st.write("Decrypted:", plaintext.decode())
        st.write(plaintext)

