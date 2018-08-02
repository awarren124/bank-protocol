from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import hashlib

class EncryptionHandler:

	initializationVector = 'This is an IV456' #16
	padCharacter = '_'
	numberThatDoesntMatter = 696969

	def uhh(self):
		return "lol"

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

	def ecc_priv_key(self):
		return keys.gen_private_key(curve.P256)

	def ecc_pub_key(self, priv_key):
		return keys.get_public_key(priv_key, curve.P256)
	
