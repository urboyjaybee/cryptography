
import streamlit as st
import hashlib

st.title("BLAKE2b Hash Generator")
st.markdown(
    """
**BLAKE2b Hash: A Fast and Secure Alternative**

BLAKE2b is a cryptographic hash function that is known for its speed and security. It was designed as a potential replacement for SHA-2 and SHA-3.

**History**

* Developed by Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian Winnerlein.
* Standardized by the IETF in RFC 7693.

**Key Points**

* **Hash Length:** Up to 512 bits (configurable)
* **Security:** Considered very secure, with no known practical attacks.
* **Usage:** Used in various applications, including file verification, password hashing, and blockchain technology.
"""
)
input_text = st.text_area("Enter text to hash:", "")

if st.button("Generate Hash"):
    hash_object = hashlib.blake2b(input_text.encode())
    hash_value = hash_object.hexdigest()
    st.success(f"BLAKE2b Hash: {hash_value}")
