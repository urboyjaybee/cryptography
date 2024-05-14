import streamlit as st
import hashlib

def generate_md5_hash(input_text):
    """Generate MD5 hash."""
    hash_object = hashlib.md5(input_text.encode())
    return hash_object.hexdigest()

def generate_sha256_hash(input_text):
    """Generate SHA-256 hash."""
    hash_object = hashlib.sha256(input_text.encode())
    return hash_object.hexdigest()

def generate_sha512_hash(input_text):
    """Generate SHA-512 hash."""
    hash_object = hashlib.sha512(input_text.encode())
    return hash_object.hexdigest()

# Streamlit app title and description
st.title("Hash Generator")

st.markdown(
    """
**Hash Generator: Generate Hashes Using Different Algorithms**

This app allows you to generate hashes using different cryptographic hash functions, including MD5, SHA-256, and SHA-512.

Select the hash algorithm from the dropdown menu, enter the text to hash, and click the "Generate Hash" button to get the hash value.
"""
)

# Dropdown to select hash algorithm
hash_algorithm = st.selectbox("Select Hash Algorithm:", ["MD5", "SHA-256", "SHA-512"])

# Text area to enter input text
input_text = st.text_area("Enter text to hash:", "")

# Button to generate hash
if st.button("Generate Hash"):
    if not input_text:
        st.warning("Please enter text to hash.")
    else:
        if hash_algorithm == "MD5":
            hash_value = generate_md5_hash(input_text)
            st.success(f"MD5 Hash: {hash_value}")
        elif hash_algorithm == "SHA-256":
            hash_value = generate_sha256_hash(input_text)
            st.success(f"SHA-256 Hash: {hash_value}")
        elif hash_algorithm == "SHA-512":
            hash_value = generate_sha512_hash(input_text)
            st.success(f"SHA-512 Hash: {hash_value}")
