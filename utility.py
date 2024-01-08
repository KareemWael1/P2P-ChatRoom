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


def format_message(message):
    # Format italic text (~italic~)
    message = message.replace('~', '\033[3m', 1)
    message = message[::-1].replace('~', 'm32[\033', 1)[::-1]

    # Format bold text (*bold*)
    message = message.replace('*', '\033[1m', 1)
    message = message[::-1].replace('*', 'm22[\033', 1)[::-1]

    # Format underline text (_underline_)
    message = message.replace('_', '\033[4m', 1)
    message = message[::-1].replace('_', 'm42[\033', 1)[::-1]

    return message