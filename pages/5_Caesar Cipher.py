import streamlit as st
from io import BytesIO

def caesar_cipher(text, shift_key, decrypt=False):
    """Encrypts or decrypts text using the Caesar Cipher.

    Args:
        text (str): The text to process.
        shift_key (int): The integer shift value.
        decrypt (bool): True for decryption, False for encryption.

    Returns:
        str: The processed text.
    """
    result = ""
    shift = shift_key if not decrypt else -shift_key  # Determine the shift direction

    for char in text:
        if 'A' <= char <= 'Z':  # Process uppercase letters
            result += chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
        elif 'a' <= char <= 'z':  # Process lowercase letters
            result += chr(((ord(char) - ord('a') + shift) % 26) + ord('a'))
        else:
            result += char  # Keep non-alphabetic characters unchanged

    return result

def caesar_cipher_file(file_content, shift_key, decrypt=False):
    """Encrypts or decrypts file content using the Caesar Cipher.

    Args:
        file_content (bytes): The file content to process.
        shift_key (int): The integer shift value.
        decrypt (bool): True for decryption, False for encryption.

    Returns:
        bytes: The processed file content.
    """
    text = file_content.decode('utf-8')
    processed_text = caesar_cipher(text, shift_key, decrypt)
    return processed_text.encode('utf-8')

# Streamlit UI setup
st.header("Caesar Cipher")

st.markdown(
    """
    **Caesar Cipher: A Classic Substitution Cipher**

    The Caesar cipher is one of the simplest and most widely known encryption techniques. 
    It's a type of substitution cipher in which each letter in the plaintext is shifted 
    a certain number of places down the alphabet.

    **History**

    - Named after Julius Caesar, who used it to protect military communications.
    - It's a simple monoalphabetic substitution cipher, meaning each letter is always 
      replaced by the same letter in the ciphertext.
    - Although easily broken, it serves as a foundational example in cryptography.

    **Pseudocode Process**

    1. **Encryption**
       - For each letter in the plaintext:
         - Determine its position in the alphabet (e.g., A=0, B=1, ...).
         - Add the shift value to the letter's position.
         - If the result goes beyond the end of the alphabet, wrap around to the beginning.
         - Find the letter at the new position in the alphabet.
         - Replace the original letter with the new letter.

    2. **Decryption**
       - Same as encryption, but subtract the shift value instead of adding.

    **Example (Shift=3):**
    Plaintext:  HELLO
    Ciphertext: KHOOR

    **Important Note:**
    The Caesar cipher is very weak due to the limited number of possible keys (26). 
    It is easily broken with frequency analysis or simple brute-force methods.
    """
)

# Text encryption/decryption
st.subheader("Text Encryption/Decryption")
text = st.text_input("Enter Text:")
shift_key = st.number_input("Enter Shift Key:", min_value=1, max_value=25, value=3, step=1, format="%d")

if st.button("Encrypt Text"):
    if not text:
        st.warning("Please enter text to encrypt.")
    else:
        encrypted_text = caesar_cipher(text, shift_key)
        st.write("Encrypted Text:", encrypted_text)

if st.button("Decrypt Text"):
    if not text:
        st.warning("Please enter text to decrypt.")
    else:
        decrypted_text = caesar_cipher(text, shift_key, decrypt=True)
        st.write("Decrypted Text:", decrypted_text)

# File encryption/decryption
st.subheader("File Encryption/Decryption")
uploaded_file = st.file_uploader("Choose a file")
file_shift_key = st.number_input("File Shift Key:", min_value=1, max_value=25, value=3, step=1, format="%d")

if uploaded_file and st.button("Encrypt File"):
    file_content = uploaded_file.read()
    encrypted_content = caesar_cipher_file(file_content, file_shift_key)
    encrypted_file = BytesIO(encrypted_content)
    encrypted_file.name = "encrypted_file.txt"
    st.download_button(label="Download Encrypted File", data=encrypted_file, file_name="encrypted_file.txt")

if uploaded_file and st.button("Decrypt File"):
    file_content = uploaded_file.read()
    decrypted_content = caesar_cipher_file(file_content, file_shift_key, decrypt=True)
    decrypted_file = BytesIO(decrypted_content)
    decrypted_file.name = "decrypted_file.txt"
    st.download_button(label="Download Decrypted File", data=decrypted_file, file_name="decrypted_file.txt")

