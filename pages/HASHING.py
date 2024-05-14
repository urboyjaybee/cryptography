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

def generate_blake2b_hash(input_text):
    """Generate BLAKE2b hash."""
    hash_object = hashlib.blake2b(input_text.encode())
    return hash_object.hexdigest()

def hash_text(input_text, hash_algorithm):
    """Generate hash for given text using specified algorithm."""
    if hash_algorithm == "MD5":
        return generate_md5_hash(input_text)
    elif hash_algorithm == "SHA-256":
        return generate_sha256_hash(input_text)
    elif hash_algorithm == "SHA-512":
        return generate_sha512_hash(input_text)
    elif hash_algorithm == "BLAKE2b":
        return generate_blake2b_hash(input_text)

def hash_file(file_contents, hash_algorithm):
    """Generate hash for given file contents using specified algorithm."""
    if hash_algorithm == "MD5":
        hash_object = hashlib.md5()
    elif hash_algorithm == "SHA-256":
        hash_object = hashlib.sha256()
    elif hash_algorithm == "SHA-512":
        hash_object = hashlib.sha512()
    elif hash_algorithm == "BLAKE2b":
        hash_object = hashlib.blake2b()

    hash_object.update(file_contents)
    return hash_object.hexdigest()

# Streamlit app title and description
st.title("Hash Generator")

st.markdown(
    """
**Hash Generator: Generate Hashes Using Different Algorithms**

This app allows you to generate hashes using different cryptographic hash functions, including MD5, SHA-256, SHA-512, and BLAKE2b.

Select the hash algorithm from the dropdown menu, enter the text to hash, or upload a file to hash, and click the "Generate Hash" button to get the hash value.
"""
)

# Dropdown to select hash algorithm
hash_algorithms = ["BLAKE2b", "MD5", "SHA-256", "SHA-512"]
hash_algorithm = st.selectbox("Select Hash Algorithm:", hash_algorithms)

# Option to input text or upload file
option = st.radio("Choose Input Source:", ("Text", "File"))

if option == "Text":
    # Text area to enter input text
    input_text = st.text_area("Enter text to hash:", "")

    # Button to generate hash for text
    if st.button("Generate Hash"):
        if not input_text:
            st.warning("Please enter text to hash.")
        else:
            hash_value = hash_text(input_text, hash_algorithm)
            st.success(f"{hash_algorithm} Hash: {hash_value}")

elif option == "File":
    # File uploader to upload a file for hashing
    uploaded_file = st.file_uploader("Upload file to hash:", type=["txt", "pdf", "docx"])

    # Button to generate hash for uploaded file
    if st.button("Generate Hash") and uploaded_file is not None:
        file_contents = uploaded_file.read()
        hash_value = hash_file(file_contents, hash_algorithm)
        st.success(f"{hash_algorithm} Hash: {hash_value}")
