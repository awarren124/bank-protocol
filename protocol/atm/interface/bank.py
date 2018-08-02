"""Backend of ATM interface for xmlrpc"""

import logging
import struct
import serial
from encryptionHandler import EncryptionHandler
eh = EncryptionHandler()



"""TODO: MAKE KEYS STORED IN A JSON FILE"""
"""TEMPORARRRYYYYY"""
key1 = b'\xe6R|\x84x\xce\x96\xa5T\xac\xd8l\xd0\xe4Lf\xf6&\x16E\xfa/\x9b\xa2\xea!\xceY\x85\xbe\ra'
key2 = b'\xb5\xd2\x03v\xad)\xd5\x8a \xa6\xa0_\x94^\xe6X=$&|&\xd4c*#M\xee[\tl\xfc\xd0'

"""~~~~~~~~~~~~~~~~~"""




class Bank:
    """Interface for communicating with the bank

    Args:
        port (serial.Serial): Port to connect to
    """

    def __init__(self, port, verbose=False):
        self.ser = serial.Serial(port, baudrate = 115200)
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
        print("bank withdraw1")
        self._vp('withdraw: Sending request to Bank')
        print("bank withdraw2")

        command = "w" # withdraw
        encCommand = eh.aesEncrypt(command, key2) #length = 16

        #len(atm_id) == 72
        print "len(atm_id):"
        print len(atm_id)
        print "len(card_id):"
        print len(card_id)
	    print(card_id)
        # data = struct.pack(">36s36sI", atm_id, card_id, amount)
        # encData = eh.aesEncrypt(data, key2)

        encAtmId = eh.aesEncrypt(atm_id, key2)
        encCardId = eh.aesEncrypt(card_id, key2)
        encAmount = eh.aesEncrypt(str(amount), key2)

        print "len(encAtmId):"
        print len(encAtmId)
        print "len(encCardId):"
        print len(encCardId)
        print "len(encAmount):"
        print len(encAmount)

        pkt = encCommand + encAtmId + encCardId + encAmount

        # encryption
        # enc_pkt = eh.aesEncrypt(pkt, key2)
        # self.ser.write(len(enc_pkt))
	    print(pkt)
        self.ser.write(pkt)
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
        enc_read_pkt = self.ser.read(16)
        dec_read_pkt = eh.aesDecrypt(enc_read_pkt, key2)
	    print("wait")
	    if dec_read_pkt == 'O':
		print("received")
		print("101")
		read_atm_id = self.ser.read(48)
		dec_atm_id = eh.aesDecrypt(read_atm_id,key2)
		print(dec_atm_id)
		print("102")
		read_card_id = self.ser.read(48)
		dec_card_id = eh.aesDecrypt(read_card_id, key2)
		print(dec_card_id)
		print("103")
		read_amount = self.ser.read(16)
		dec_amount = eh.aesDecrypt(read_amount, key2)
		print(dec_amount)
		print("hii")
        #aid, cid = struct.unpack(">36s36s", pkt)
        if dec_atm_id == atm_id and dec_card_id == card_id:
            self._vp('withdraw: Withdrawal accepted')
            return True
        else:
            return false

    def regenerate(self, atm_id, card_id):
        command = ''
        while command != 'a':
            command = self.ser.read(1)
        rec_atm_id = self.ser.read()
        rec_card_id = self.ser.read()
        rec_new_key1 = self.ser.read()
        rec_new_key2 = self.ser.read()
        rec_new_IV = self.ser.read()
        dec_IV = eh.aesDecrypt(rec_new_IV,key2)
        eh.regenerate(dec_IV)
        dec_atm_id = eh.aesDecrypt(rec_atm_id, key2)
        dec_card_id = eh.aesDecrypt(rec_card_id, key2)
        dec_new_key1 = eh.aesDecrypt(rec_new_key1, key2)
        dec_new_key2 = eh.aesDecrypt(rec_new_key2, key2)#figure out how to store keys securely
        if dec_atm_id == atm_id and dec_card_id == atm.id:
            #replace
        else:
            return false

    def provision_update(self, uuid, pin, balance):
        pkt = struct.pack(">36s8sI", uuid, pin, balance)
        self.ser.write("p" + pkt)

    def provision_key(self, new_key1, new_key2):
        key1 = new_key1
        key2 = new_key2
        self.ser.write("a" + new_key1 + new_key2)

    def send_key1(self, key1):
        return key1



