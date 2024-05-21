from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

output_file = 'encrypyed.bin'
data = b'Dongeui University, Dept. of Computer Engr'
key = b'\xb0\xc0\xfc\x9f,Xg\x08\n%/\x8f\x8c"c\x91\xa8\xa1b\xe9\xa4\xf4\x0b\xb5y\x08^6\xa3\x0e\x05\x00'

cipher = AES.new(key, AES.MODE_CBC)
ciphered_data = cipher.encrypt(pad(data, AES.block_size))

file_out = open(output_file, "wb")
file_out.write(cipher.iv)
file_out.write(ciphered_data)
file_out.close()
