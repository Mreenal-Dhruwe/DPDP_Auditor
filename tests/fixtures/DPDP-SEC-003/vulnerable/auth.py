import hashlib


def hash_password(raw):
    return hashlib.md5(raw.encode()).hexdigest()


def store(user, form):
    user.password_digest = hashlib.sha1(form["password"].encode()).hexdigest()


def legacy_check(user, password):
    h = hashlib.sha256()
    h.update(password.encode())
    return h.hexdigest() == user.password_hash
