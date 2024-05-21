from hashlib import md5

msg = 'I lone Python'
m = md5()
m.update(msg.encode('utf-8'))
ret = m.hexdigest()
print(ret)
