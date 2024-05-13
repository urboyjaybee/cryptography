
import streamlit as st
import hashlib

st.title("MD5 Hash Generator")
Python
# filename: md5_hash.py
import streamlit as st
import hashlib

st.title("MD5 Hash Generator")

st.markdown(
    """
**MD5 Hash: A Widely Used But Less Secure Hash**

MD5 (Message-Digest Algorithm 5) is a cryptographic hash function that produces a 128-bit hash value. It was once widely used for verifying data integrity, but it is now considered insecure for cryptographic purposes.

**History**

* Developed in 1991 by Ronald Rivest.
* Designed to be a successor to MD4.
* Widely adopted for various applications, including checksums and digital signatures.

**Key Points**

* **Hash Length:** 128 bits (32 hexadecimal characters)
* **Security:** No longer considered secure for cryptographic applications due to vulnerabilities to collision attacks.
* **Usage:** Still used for non-cryptographic purposes, like checksums to verify file integrity.
"""
)

input_text = st.text_area("Enter text to hash:", "")

if st.button("Generate Hash"):
    hash_object = hashlib.md5(input_text.encode())
    hash_value = hash_object.hexdigest()
    st.success(f"MD5 Hash: {hash_value}")
