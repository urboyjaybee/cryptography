import streamlit as st

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

text = st.text_input("Enter Text:")
shift_key = st.number_input("Enter Shift Key:", min_value=1, max_value=25, value=3, step=1, format="%d")

if st.button("Encrypt"):
    if not text:
        st.warning("Please enter text to encrypt.")
    else:
        encrypted_text = caesar_cipher(text, shift_key)
        st.write("Encrypted Text:", encrypted_text)

if st.button("Decrypt"):
    if not text:
        st.warning("Please enter text to decrypt.")
    else:
        decrypted_text = caesar_cipher(text, shift_key, decrypt=True)
        st.write("Decrypted Text:", decrypted_text)
