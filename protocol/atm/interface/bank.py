"""Backend of ATM interface for xmlrpc"""

import logging
import struct
import serial
from encryptionHandlerInterface import EncryptionHandlerInterface
from atm_db import DB
eh = EncryptionHandlerInterface()



"""TODO: MAKE KEYS STORED IN A JSON FILE"""
"""TEMPORARRRYYYYY"""
key1 = b'\xe6R|\x84x\xce\x96\xa5T\xac\xd8l\xd0\xe4Lf\xf6&\x16E\xfa/\x9b\xa2\xea!\xceY\x85\xbe\ra'
key2 = b'\xb5\xd2\x03v\xad)\xd5\x8a \xa6\xa0_\x94^\xe6X=$&|&\xd4c*#M\xee[\tl\xfc\xd0'
private_key = ''


"""~~~~~~~~~~~~~~~~~"""

class Bank:
    """Interface for communicating with the bank

    Args:
        port (serial.Serial): Port to connect to
    """

    def __init__(self, port, verbose=False, db_path="atmcontents.json"):
        self.ser = serial.Serial(port, baudrate = 115200)
        self.atm_db = DB(db_path=db_path)  # figure this out, not sure if it will work
        self.verbose = verbose

    def _vp(self, msg, stream=logging.info):
        """Prints message if verbose was set

        Args:
            msg (str): message to print
            stream (logging function, optional): logging function to call
        """
        if self.verbose:
            stream("card: " + msg)

    def check_balance(self, atm_id, card_id, pin):
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
            return False

    def withdraw(self, atm_id, card_id, pin, amount):
        """Requests a withdrawal from the account associated with the card_id

        Args:
            atm_id (str): UUID of the HSM
            card_id (str): UUID of the ATM card
            amount (str): Requested amount to withdraw

        Returns:
            str: hsm_id on success
            bool: False on failure
        """
        key2 = self.atm_db.admin_get_key("BankKey")
        magic_word1 = self.atm_db.admin_get_key("magicWord1")
        private_key = self.atm_db.admin_get_key("RSAprivate")
        # magic_word1 = eh.aesDecrypt(magic_word1, key2)#atm decrypts magic word1
        print("bank withdraw1")
        self._vp('withdraw: Sending request to Bank')
        print("bank withdraw2")
        hash_magic = eh.hash(magic_word1)
        print(len(hash_magic))
        self.ser.write("a")  # start byte

        self.ser.write(hash_magic)  # verification, sends hashed version of magicword1 so the bank, can use it to compare, and verify the atm
        firstHalf = self.spliceSecondHalf(key2)  # split key, and send over first half to be combined with the second half, so it could be properly used
        print(len(firstHalf))
        command = "w" # withdraw
        self.ser.write(firstHalf)

        print("len(AtmId):")
        print(len(atm_id))
        print("len(CardId):")
        print(len(card_id))
        print("len(Amount):")
        print(len(str(amount)))
        print("len(Pin):")
        print(len(str(pin)))

        pkt = command + atm_id + card_id + str(amount) + str(pin)
        enc_pkt = eh.aesEncrypt(pkt, key2)

        # len(atm_id) == 72

        # data = struct.pack(">36s36sI", atm_id, card_id, amount)
        # encData = eh.aesEncrypt(data, key2)


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
        entire_packet = self.ser.read()     # change to fit RSA  ======================================
        dec_pkt = eh.RSA_decrypt(entire_packet, private_key)

        command = dec_pkt[0]# get o from decrypted concatenated string
        print("wait")
        if command == 'O':
            #figure out the lengths of each individual things that was encrypted to seperate each important piece
            dec_atm_id = eh.RSA_decrypt(read_atm_id, private_key)
            print(dec_atm_id)
            print("102")
            # figure out the lengths of each individual things that was encrypted to seperate each important piece
            dec_card_id = eh.RSA_decrypt(read_card_id, private_key)
            print(dec_card_id)
            print("103")
            # figure out the lengths of each individual things that was encrypted to seperate each important piece
            dec_amount = eh.RSA_decrypt(read_amount, private_key)
            print(dec_amount)
            print("hii")
            dec_magic_word2 = eh.RSA_decrypt(read_amount, private_key)
            # figure out the lengths of each individual things that was encrypted to seperate each important piece
            # aid, cid = struct.unpack(">36s36s", pkt)
            if dec_magic_word2 == self.atm_db.admin_get_key("magicWord2"):#checks magic word for verification
                self._vp('withdraw: Withdrawal accepted')
                return True
            else:
                return False

    def regenerate(self, atm_id, card_id):
        private_key = self.atm_db.admin_get_key("RSAprivate")
        command = ''
        while command != 'r':
            command = self.ser.read(1)  # receives everything from bank
        # rec_new_key1 = self.ser.read()
        rec_new_key2 = self.ser.read()
        rec_new_IV = self.ser.read()
        dec_IV = eh.RSA_decrypt(rec_new_IV, private_key)
        eh.initializationVector = dec_IV
        rec_new_magic1 = self.ser.read()  # find lengths=============================================================================
        rec_new_magic2 = self.ser.read()
        ver_magic1 = self.ser.read()
        ver_magic2 = self.ser.read()
        dec_new_key2 = eh.RSA_decrypt(rec_new_key2, private_key)
        dec_new_magic1 = eh.RSA_decrypt(rec_new_magic1, private_key)
        dec_new_magic2 = eh.RSA_decrypt(rec_new_magic2, private_key)
        dec_ver_magic1 = eh.RSA_decrypt(ver_magic1, private_key)
        dec_ver_magic2 = eh.RSA_decrypt(ver_magic2, private_key)
        if dec_ver_magic1 == self.atm_db.admin_get_key("magicWord1") and dec_ver_magic2 == self.atm_db.admin_get_key("magicWord2"):#check line syntax, checks to verify the bank is the bank
            self.atm_db.admin_set_key(dec_new_key2, "BankKey")  # replaces bank key with new key
            self.atm_db.admin_set_key(dec_new_magic1, "magicWord1")  # replaces magic words
            self.atm_db.admin_set_key(dec_new_magic2, "magicWord2")  # replaces magic words

    def provision_update(self, uuid, pin, balance):
        pkt = struct.pack(">36s8sI", uuid, pin, balance)
        self.ser.write("p" + pkt)

    def provision_key(self,new_key2, pubkey, magicWord1, magicWord2):
        self.ser.write("a"  + new_key2 + pubkey + magicWord1 + magicWord2)#sends the bank key2, the pub key, and the 2 encrypted magicwords

    def spliceSecondHalf(self, string):
        return string[:len(string)/2]


