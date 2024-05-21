from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

salt = get_random_bytes(32)
password = 'password123'
key = PBKDF2(password, salt, dkLen=32)
print(key)
