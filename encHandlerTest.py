from encryptionHandler import EncryptionHandler
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

encryptionHandler = EncryptionHandler()
aesKey = '0123456789abcdef0123456789abcdef' #32 bytes
message = '0123456789abcdef'
rsaKey = RSA.generate(2048)
byteMessage = message.encode('utf-8')
publicKey = rsaKey.publickey().exportKey()
privateKey = rsaKey.exportKey()
ciph1 = encryptionHandler.aesEncrypt('0123456789abcde', aesKey)
plain1 = encryptionHandler.aesDecrypt(ciph1, aesKey)
if(plain1 == '0123456789abcde'):
	print("✅ ✅ ✅ AES encrypt/decrypt test complete ✅ ✅ ✅")
else:
	print("⛔ ⛔ ⛔ AES encrypt/decrypt test failed ⛔ ⛔ ⛔")

ciph2 = encryptionHandler.rsaEncrypt('test2', publicKey)
plain2 = encryptionHandler.rsaDecrypt(ciph2, privateKey)
if(plain2 == 'test2'):
	print("✅ ✅ ✅ RSA encrypt/decrypt test complete ✅ ✅ ✅")
else:
	print("⛔ ⛔ ⛔ RSA encrypt/decrypt test failed ⛔ ⛔ ⛔")

