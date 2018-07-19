from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

class EncryptionHandler:

	initializationVector = 'This is an IV456' #16
	padCharacter = '+'
	numberThatDoesntMatter = 696969

	def uhh(self):
		return "lol"

	def aesEncrypt(self, plaintext, key):
		aes = AES.new(key, AES.MODE_CBC, self.initializationVector)
		offset = (16-len(plaintext) % 16)
		plaintext += (self.padCharacter * offset)
=		ciphertext = aes.encrypt(plaintext)
		return ciphertext
	def aesDecrypt(self, ciphertext, key):
		aes = AES.new(key, AES.MODE_CBC, self.initializationVector)
		plaintext = aes.decrypt(ciphertext).decode('utf-8')
		plaintext = plaintext[:plaintext.find(self.padCharacter)]
		return plaintext
	def rsaEncrypt(self, plaintext, key):
		rsa = RSA.importKey(key)
		plaintext = plaintext.encode('utf-8')
		ciphertext = rsa.encrypt(plaintext, self.numberThatDoesntMatter)[0]
		return ciphertext
	
	def rsaDecrypt(self, ciphertext, key):
		rsa = RSA.importKey(key)
		plaintext = rsa.decrypt(ciphertext).decode('utf-8')
		return plaintext

	def hash(self, plaintext):
		return hashlib.sha256(plaintext.encode('utf-8')).digest()



    
    def test():
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
    test()
