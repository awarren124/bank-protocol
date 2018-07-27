from Crypto.Cipher import AES


key = '0123456789abcdef0123456789abcdef' #32 bytes

iv = 'This is an IV456' #16

aes = AES.new(key, AES.MODE_CBC, iv)
message = '0123456789abcdef'
offset = (16-len(message) % 16)
message += ('ㄻ'*offset)
ciphertext = aes.encrypt(message)
# print(ciphertext)
aes2 = AES.new(key, AES.MODE_CBC, iv)
plaintext = aes2.decrypt(ciphertext).decode('utf-8')
plaintext = plaintext[:plaintext.find('ㄻ')]

# print(plaintext)
