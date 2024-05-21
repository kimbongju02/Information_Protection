from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

input_file = 'encrypyed.bin'
key = b'\xb0\xc0\xfc\x9f,Xg\x08\n%/\x8f\x8c"c\x91\xa8\xa1b\xe9\xa4\xf4\x0b\xb5y\x08^6\xa3\x0e\x05\x00'
# the key you generated
# read the data from the file
file_in = open(input_file, 'rb')
iv = file_in.read(16)
cipher_data = file_in.read()
file_in.close()

# Create Cipher object and encrypt the data
cipher = AES.new(key, AES.MODE_CBC, iv=iv) # setup cipher
original_data = unpad(cipher.decrypt(cipher_data), AES.block_size) # decrypt and unPad
print(original_data)
decrypted_data = original_data.decode('utf-8')
print(decrypted_data)
