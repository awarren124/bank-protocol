from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import hashlib
import rsa

class EncryptionHandler:

	initializationVector = 'This is an IV456' #16
	padCharacter = '_'
	numberThatDoesntMatter = 696969

	def uhh(self):
		return "lol"
	def set_IV(self, newIV):
		initializationVector = newIV
	def aesEncrypt(self, plaintext, key):
		aes = AES.new(key, AES.MODE_CBC, self.initializationVector)
		offset = (16-len(plaintext) % 16)
		plaintext += (self.padCharacter * offset)
		ciphertext = aes.encrypt(plaintext)
		return ciphertext
	def aesDecrypt(self, ciphertext, key):
		print "aesDecrypt"
		print "ciphertext: " + ciphertext
		aes = AES.new(key, AES.MODE_CBC, self.initializationVector)
		plaintext = aes.decrypt(ciphertext)#.decode('utf-8')
		plaintext = plaintext[:plaintext.find(self.padCharacter)]
		print "plaintext: " + plaintext
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
		print plaintext
		return hashlib.sha256(plaintext.encode('utf-8')).digest()

	def gen_key_pair(self):
		(pubkey, privkey) = rsa.newkeys(512)
		return pubkey, privkey

	def RSA_encrypt(self, cipherText, publicKey):
		return rsa.encrypt(cipherText, publicKey)

	def RSA_decrypt(self, cipherText, priavteKey):
		message = rsa.decrypt(cipherText, privateKey).decode('utf-8')
		return message
