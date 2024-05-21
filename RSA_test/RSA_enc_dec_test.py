from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# This module converts binary data to hexadecimal
from binascii import hexlify

# Create an RSA key pair with a key size of 1024 bit
key = RSA.generate(1024)

# set the private_key variable to the generated key
private_key = key

# derive the public key from the generated key
public_key = key.publickey()

# creatae a PKCS1_OAEP cipher object with the public key for encrpytion
data_to_encrypt = b"Hello, this a message to be encrypted."
cipher_rsa = PKCS1_OAEP.new(public_key)

# encrypt the provided data using the public key
encrpyted = cipher_rsa.encrypt(data_to_encrypt)

# convert binary data to hexadecimal for display using hexlify
print("Encrypted: ", hexlify(encrpyted))

# create a PKCS1_OAEP cipher object with the private key for decryption
cipher_rsa = PKCS1_OAEP.new(private_key)
decrypted = cipher_rsa.decrypt(encrpyted)

# display the decrypted result as a UTF-8 encodes string
print("decryptes: ", decrypted.decode("utf-8"))
