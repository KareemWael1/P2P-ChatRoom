import hashlib


def hash_password(password):
    # Encode the password string to bytes before hashing
    password_bytes = password.encode('utf-8')
    # Create an SHA-256 hash object
    sha256 = hashlib.sha256()
    # Update the hash object with the password bytes
    sha256.update(password_bytes)
    # Get the hexadecimal representation of the hashed password
    hashed_password = sha256.hexdigest()
    return hashed_password
