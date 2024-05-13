import streamlit as st

st.header("Caesar Cipher")

st.markdown(
    """
**Caesar Cipher: A Classic Substitution Cipher**

The Caesar cipher is one of the simplest and most widely known encryption techniques. It's a type of substitution cipher in which each letter in the plaintext is shifted a certain number of places down the alphabet.

**History**

* Named after Julius Caesar, who used it to protect military communications.
* It's a simple monoalphabetic substitution cipher, meaning each letter is always replaced by the same letter in the ciphertext.
* Although easily broken, it serves as a foundational example in cryptography.

**Pseudocode Process**

1. **Encryption**
   * For each letter in the plaintext:
      * Determine its position in the alphabet (e.g., A=0, B=1, ...).
      * Add the shift value to the letter's position.
      * If the result goes beyond the end of the alphabet, wrap around to the beginning.
      * Find the letter at the new position in the alphabet.
      * Replace the original letter with the new letter.

2. **Decryption**
   * Same as encryption, but subtract the shift value instead of adding.

**Example (Shift=3):**
Plaintext:  HELLO
Ciphertext: KHOOR

**Important Note:** The Caesar cipher is very weak due to the limited number of possible keys (26). It is easily broken with frequency analysis or simple brute-force methods.
"""
)

def encrypt_decrypt(text, shift_keys, ifdecrypt):
    """Encrypts or decrypts text using the Caesar Cipher.

    Args:
        text: The text to process.
        shift_keys: A list of integer shift values.
        encrypt: True for encryption, False for decryption.

    Returns:
        The processed text.
    """

    result = ""
    if len(shift_keys) <=1 or len(shift_keys) > len(text):
        raise ValueError("Invalid")
        
    
    for i, char in enumerate(text):
        shift = shift_keys[i % len(shift_keys)]
        
        if 32 <= ord(char) <= 125:
            new_ascii = ord(char) + shift if not ifdecrypt else ord(char) - shift
            while new_ascii > 125:
                new_ascii -= 94
            while new_ascii < 32:
                new_ascii += 94
                
            result += chr(new_ascii)
        else:
            result += char
        st.write(str(i) + " ", char, str(shift), result [i])
    return result

# Streamlit UI setup
text = st.text_input("Text")
shift_keys_str = st.text_input("Shift keys (space-separated)")
shift_keys = [int(key) for key in shift_keys_str.split()]

if st.button("Submit"):
    if not shift_keys:
        st.error("Please enter shift keys.")
    else:
        encrypted_text = encrypt_decrypt(text, shift_keys, False)
        decrypted_text = encrypt_decrypt(encrypted_text, shift_keys, True)

        st.write("----------")
        st.write("Text:", text)
        st.write("Shift keys:", shift_keys_str)
        st.write("Cipher:", encrypted_text)
        st.write("Decrypted text:", decrypted_text)

