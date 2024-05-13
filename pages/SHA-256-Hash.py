
import streamlit as st
import hashlib

st.title("SHA-256 Hash Generator")
st.markdown(
    """
**SHA-256 Hash: A Secure Workhorse for Modern Applications**

SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function designed by the NSA. It's a member of the SHA-2 family and is widely used for various security applications.

**History**

* Published in 2001 by the National Institute of Standards and Technology (NIST).
* Designed to address weaknesses found in SHA-1.
* Has become one of the most popular hash functions due to its security and performance.

**Key Points**

* **Hash Length:** 256 bits (64 hexadecimal characters)
* **Security:** Considered secure for most cryptographic purposes, with no known practical attacks.
* **Usage:** Used in a wide range of applications, including digital signatures, password hashing, and blockchain technology.
"""
)
input_text = st.text_area("Enter text to hash:", "")

if st.button("Generate Hash"):
    hash_object = hashlib.sha256(input_text.encode())
    hash_value = hash_object.hexdigest()
    st.success(f"SHA-256 Hash: {hash_value}")
