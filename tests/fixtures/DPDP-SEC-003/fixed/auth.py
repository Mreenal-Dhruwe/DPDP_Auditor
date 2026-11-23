import hashlib
import os

import bcrypt


def hash_password(raw):
    return bcrypt.hashpw(raw.encode(), bcrypt.gensalt())


def derive_key(password, salt=None):
    salt = salt or os.urandom(16)
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)


def file_checksum(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()
