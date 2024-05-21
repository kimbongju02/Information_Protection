from Crypto.Random import get_random_bytes
key_location = "My_key.bin"

key = get_random_bytes(32)

file_out = open(key_location, "wb")
file_out.write(key)
file_out.close()

file_in = open(key_location, "rb")
key_from_file = file_in.read()
file_in.close()

assert key == key_from_file, 'keys do not match'
