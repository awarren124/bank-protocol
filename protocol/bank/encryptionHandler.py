from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import hashlib
import rsa
import base64

class EncryptionHandler:

	initializationVector = 'This is an IV456' #16
	padCharacter = '_'
	numberThatDoesntMatter = 696969

	def uhh(self):
		return "lol"

	def set_IV(self, newIV):
		initializationVector = newIV
	def aesEncrypt(self, plaintext, key):
		plaintext = str(plaintext)
		aes = AES.new(key, AES.MODE_CBC, self.initializationVector)
		offset = (16-len(plaintext) % 16)
		plaintext += (self.padCharacter * offset)
		ciphertext = aes.encrypt(plaintext)
		ciphertext = base64.b64encode(ciphertext)
		return ciphertext
	def aesDecrypt(self, ciphertext, key):
		aes = AES.new(key, AES.MODE_CBC, self.initializationVector)
		print(ciphertext)
		ciphertext = base64.b64decode(ciphertext)
		print(ciphertext)
		plaintext = str(aes.decrypt(ciphertext))
		print(plaintext)
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
		return hashlib.sha256(plaintext).hexdigest()

	def hashRaw(self, plaintext):
		return hashlib.sha256(plaintext).digest()

	def gen_key_pair(self):
		(pubkey, privkey) = rsa.newkeys(2048)
		return pubkey, privkey

	def RSA_encrypt(self, cipherText, publicKey):
		cipherText = cipherText.encode('utf-8')
		return rsa.encrypt(cipherText, publicKey)

	def RSA_decrypt(self, cipherText, priavteKey):
		message = rsa.decrypt(cipherText, privateKey).decode('utf-8')
		return message