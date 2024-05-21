from hashlib import sha256

msg = 'I lone Python'
m = sha256()
m.update(msg.encode('utf-8'))
ret = m.hexdigest()
print(ret)
