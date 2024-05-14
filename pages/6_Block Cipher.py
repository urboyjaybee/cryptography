import streamlit as st

def pad(data, block_size):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

def xor_encrypt_block(plaintext_block, key):
    encrypted_block = b''
    for i in range(len(plaintext_block)):
        encrypted_block += bytes([plaintext_block[i] ^ key[i % len(key)]])
    return encrypted_block

def xor_decrypt_block(ciphertext_block, key):
    return xor_encrypt_block(ciphertext_block, key)  # XOR decryption is same as encryption

def xor_encrypt(plaintext, key, block_size):
    padded_plaintext = pad(plaintext, block_size)
    encrypted_data = b''
    for i in range(0, len(padded_plaintext), block_size):
        plaintext_block = padded_plaintext[i:i+block_size]
        encrypted_block = xor_encrypt_block(plaintext_block, key)
        encrypted_data += encrypted_block
    return encrypted_data

def xor_decrypt(ciphertext, key, block_size):
    decrypted_data = b''
    for i in range(0, len(ciphertext), block_size):
        ciphertext_block = ciphertext[i:i+block_size]
        decrypted_block = xor_decrypt_block(ciphertext_block, key)
        decrypted_data += decrypted_block
    unpadded_decrypted_data = unpad(decrypted_data)
    return unpadded_decrypted_data

def main():
    st.title("Block Cipher - XOR Encryption")

    st.markdown(
        """
        **Block Ciphers: Building Blocks of Modern Cryptography**

        Block ciphers are symmetric encryption algorithms that operate on fixed-length 
        groups of bits called blocks. They transform plaintext blocks into ciphertext 
        blocks using a secret key.

        **History**

        - Originated in the mid-20th century, with DES (Data Encryption Standard) as 
          an early example.
        - AES (Advanced Encryption Standard) is a widely used modern block cipher.
        - Offer greater security than simple stream ciphers due to their ability to 
          diffuse and confuse data within blocks.

        **Pseudocode Process (XOR Example)**

        1. **Padding:**
           - If the plaintext isn't a multiple of the block size, add padding to 
             make it fit.

        2. **Encryption**
           - Divide the plaintext into blocks.
           - For each block:
              - Apply the XOR operation to each bit in the block with the 
                corresponding bit in the key.
              - The result is the ciphertext block.

        3. **Decryption**
           - Same as encryption, but applying XOR with the key to the ciphertext 
             blocks recovers the original plaintext.

        **Example (Block Size = 8 bits, Key = 10101010):**
        Plaintext block: 01101001
        Key:            10101010
        Ciphertext block: 11000011

        **Important Note:** This is a simplified example using XOR. Real block ciphers 
        like AES use much more complex transformations to provide strong security.
        """
    )

    plaintext = st.text_input("Plaintext:")
    key = st.text_input("Key:")
    block_size = st.number_input("Block Size:", min_value=1, max_value=1024, value=8, step=1)

    encrypt_button = st.button("Encrypt")
    decrypt_button = st.button("Decrypt")

    if encrypt_button and plaintext and key and block_size:
        key_bytes = bytes(key, encoding='utf-8')
        encrypted_data = xor_encrypt(bytes(plaintext, encoding='utf-8'), key_bytes, block_size)
        st.subheader("Encrypted Data:")
        st.write(encrypted_data.hex())

    if decrypt_button and plaintext and key and block_size:
        key_bytes = bytes(key, encoding='utf-8')
        decrypted_data = xor_decrypt(bytes.fromhex(plaintext), key_bytes, block_size)
        st.subheader("Decrypted Data:")
        st.write(decrypted_data.decode('utf-8'))

if __name__ == "__main__":
    main()
