"""Backend of ATM interface for xmlrpc"""

import logging
import struct
import serial
from encryptionHandler import EncryptionHandler
from atm_db import DB
eh = EncryptionHandler()



"""TODO: MAKE KEYS STORED IN A JSON FILE"""
"""TEMPORARRRYYYYY"""
key1 = b'\xe6R|\x84x\xce\x96\xa5T\xac\xd8l\xd0\xe4Lf\xf6&\x16E\xfa/\x9b\xa2\xea!\xceY\x85\xbe\ra'
key2 = b'\xb5\xd2\x03v\xad)\xd5\x8a \xa6\xa0_\x94^\xe6X=$&|&\xd4c*#M\xee[\tl\xfc\xd0'
private_key = ''
magic_word1 = ''

"""~~~~~~~~~~~~~~~~~"""




class Bank:
    """Interface for communicating with the bank

    Args:
        port (serial.Serial): Port to connect to
    """

    def __init__(self, port, verbose=False, db_path="atm_content.json"):
        self.ser = serial.Serial(port, baudrate = 115200)
        self.db = db.DB(db_path=db_path)#figure this out, not sure if it will work
        self.verbose = verbose

    def _vp(self, msg, stream=logging.info):
        """Prints message if verbose was set

        Args:
            msg (str): message to print
            stream (logging function, optional): logging function to call
        """
        if self.verbose:
            stream("card: " + msg)

    def check_balance(self, atm_id, card_id):
        """Requests the balance of the account associated with the card_id

        Args:
            atm_id (str): UUID of the ATM
            card_id (str): UUID of the ATM card to look up

        Returns:
            str: Balance of account on success
            bool: False on failure
        """
        self._vp('check_balance: Sending request to Bank')
	print("check1")
	enc_command = eh.aesEncrypt("b", key2)
	enc_atm_id = eh.aesEncrypt(atm_id, key2)
	enc_card_id = eh.aesEncrypt(card_id, key2)
    enc_pkt = enc_command + enc_atm_id + enc_card_id
	print("enc_pkt")
    self.ser.write(enc_pkt)
	"""
	pkt = ""
        while pkt not in "ONE":
            pkt = self.ser.read()
        if pkt != "O":
            return False
        pkt = self.ser.read(76)
        #aid, cid, bal = struct.unpack(">36s36sI", pkt)
	"""
	cmd = ""
	while cmd != 'a':
	    print("initialized")
	    cmd = self.ser.read(1)
	decision = self.ser.read(16)
	dec_decision = eh.aesDecrypt(decision, key2)
	if dec_decision == 'O':
	    aid = self.ser.read(48)
	    cid = self.ser.read(48)
	    bal = self.ser.read(16)	
	    dec_aid = eh.aesDecrypt(aid, key2)
	    dec_cid = eh.aesDecrypt(cid, key2)
	    dec_bal = eh.aesDecrypt(bal, key2)
	    print(dec_bal)
            self._vp('check_balance: returning balance')
            return dec_bal
	else:
	    return false

    def withdraw(self, atm_id, card_id, amount):
        """Requests a withdrawal from the account associated with the card_id

        Args:
            atm_id (str): UUID of the HSM
            card_id (str): UUID of the ATM card
            amount (str): Requested amount to withdraw

        Returns:
            str: hsm_id on success
            bool: False on failure
        """
        magic_word1 = eh.aesDecrypt(magic_word1, key2)#atm decrypts magic word1
        print("bank withdraw1")
        self._vp('withdraw: Sending request to Bank')
        print("bank withdraw2")
        self.ser.write(eh.hash(magic_word))#verification, sends hashed version of magicword1 so the bank, can use it to compare, and verify the atm
        firstHalf = spliceFirstHalf(key2)# split key, and send over first half to be combined with the second half, so it could be properly used
        self.ser.write(firstHalf)
        command = "w" # withdraw
        encCommand = eh.aesEncrypt(command, key2) #length = 16, encrypts command

        #len(atm_id) == 72
        print "len(atm_id):"
        print len(atm_id)
        print "len(card_id):"
        print len(card_id)
	    print(card_id)
        # data = struct.pack(">36s36sI", atm_id, card_id, amount)
        # encData = eh.aesEncrypt(data, key2)

        encAtmId = eh.aesEncrypt(atm_id, key2)#encrypts atm_id
        encCardId = eh.aesEncrypt(card_id, key2)#encrypts_card id
        encAmount = eh.aesEncrypt(str(amount), key2)#encrypts amount

        print "len(encAtmId):"
        print len(encAtmId)
        print "len(encCardId):"
        print len(encCardId)
        print "len(encAmount):"
        print len(encAmount)

        pkt = encCommand + encAtmId + encCardId + encAmount#sends encrypted data over the bank
        #///////////////////////////////////////////////////////////////////////////////////////////////////
        # encryption
        # enc_pkt = eh.aesEncrypt(pkt, key2)
        # self.ser.write(len(enc_pkt))
	    print(pkt)
        self.ser.write(pkt)#sends
	    print("sent")
        # while pkt not in "ONE":
        #     pkt = self.ser.read()
        # if pkt != "O":
        #     self._vp('withdraw: request denied')
        #     return False
        enc_read_pkt = ''
	    tempPacket = ''
        while tempPacket != 'a':
	        tempPacket = self.ser.read()
	        print("hi")
        enc_read_pkt = self.ser.read(16)#change to fit RSA
        enc_read_pkt = eh.RSA_decrypt(enc_read_pkt, private_key)
        dec_read_pkt = eh.aesDecrypt(enc_read_pkt, key2)
	    print("wait")
	    if dec_read_pkt == 'O':
		    print("received")
		    print("101")
		    read_atm_id = self.ser.read(48)#change to fit RSA
            read_atm_id = eh.RSA_decrypt(read_atm_id, private_key)
		    dec_atm_id = eh.aesDecrypt(read_atm_id,key2)
		    print(dec_atm_id)
		    print("102")
		    read_card_id = self.ser.read(48)#change to fit RSA
            read_card_id = eh.RSA_decrypt(read_card_id, private_key)
		    dec_card_id = eh.aesDecrypt(read_card_id, key2)
		    print(dec_card_id)
		    print("103")
		    read_amount = self.ser.read(16)#change to fit RSA
            read_amount = eh.RSA_decrypt(read_amount, private_key)
		    dec_amount = eh.aesDecrypt(read_amount, key2)
		    print(dec_amount)
		    print("hii")
        #aid, cid = struct.unpack(">36s36s", pkt)
        if dec_atm_id == atm_id and dec_card_id == card_id:#check statement, check tampering? pointless right now
            self._vp('withdraw: Withdrawal accepted')
            return True
        else:
            return false

    def regenerate(self, atm_id, card_id):
        private_key = self.
        command = ''
        while command != 'r':
            command = self.ser.read(1)
        rec_atm_id = self.ser.read()
        rec_card_id = self.ser.read()
        rec_new_key1 = self.ser.read()
        rec_new_key2 = self.ser.read()
        rec_new_IV = self.ser.read()
        dec_IV = eh.RSA_decrypt(rec_new_IV,private_key)
        eh.set_IV(dec_IV)
        dec_atm_id = eh.RSA_decrypt(rec_atm_id,private_key)
        dec_card_id = eh.RSA_decrypt(rec_card_id,private_key)
        dec_new_key1 = eh.RSA_decrypt(rec_new_key1,private_key)
        dec_new_key2 = eh.RSA_decrypt(rec_mew_key2,private_key)#figure out how to store keys securely
        if dec_atm_id == atm_id and dec_card_id == atm.id:
            #replace
        else:
            return false

    def provision_update(self, uuid, pin, balance):
        pkt = struct.pack(">36s8sI", uuid, pin, balance)
        self.ser.write("p" + pkt)

    def provision_key(self,new_key2, pubkey, magicWord1, magicWord2):
        self.ser.write("a" + spliceSecondHalf(new_key2) + pubkey + magicWord1 + magicWord2)#sends the bank half of key2, the pub key, and the 2 encrypted magicwords

    def spliceSecondHalf(self, string):
        return string[:len(string)/2]


