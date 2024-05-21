import hashlib

string = b"My name is apple and I am a vegetable?"
sha256 = hashlib.sha256()
sha256.update(string)
string_hash = sha256.hexdigest()
print(f"Hash:{string_hash}")
