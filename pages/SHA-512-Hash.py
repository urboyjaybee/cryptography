
import streamlit as st
import hashlib

st.title("SHA-512 Hash Generator")
st.markdown(
    """
**SHA-512 Hash: Enhanced Security with a Larger Digest**

SHA-512 (Secure Hash Algorithm 512-bit) is another member of the SHA-2 family, similar to SHA-256 but with a larger output size.

**History**

* Published along with SHA-256 in 2001 by NIST.
* Designed for systems that require a higher level of security or longer hash values.

**Key Points**

* **Hash Length:** 512 bits (128 hexadecimal characters)
* **Security:** Considered very secure, with no known practical attacks.
* **Usage:** Used in similar applications as SHA-256 but where a larger hash output is desired for added security.
"""
)
input_text = st.text_area("Enter text to hash:", "")

if st.button("Generate Hash"):
    hash_object = hashlib.sha512(input_text.encode())
    hash_value = hash_object.hexdigest()
    st.success(f"SHA-512 Hash: {hash_value}")
