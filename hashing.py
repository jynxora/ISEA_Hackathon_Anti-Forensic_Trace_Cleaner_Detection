import hashlib

def hash_file(path: str) -> str:
    sha256 = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):  # 1MB chunks
            sha256.update(chunk)

    return sha256.hexdigest()
