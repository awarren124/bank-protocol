"""Backend of ATM interface for xmlrpc"""

import logging
import struct
import serial
from encryptionHandler import EncryptionHandlerInterface
from atm_db import ATM_DB
import Adafruit_BBIO.UART as UART

UART.setup("UART4")
UART.setup("UART1")

eh = EncryptionHandlerInterface()
SPACING = '+'
PADDING = '_'


class Bank:
    """Interface for communicating with the bank from the ATM

    Args:
        port (serial.Serial): Port to connect to
    """
    GOOD = "O"
    BAD = "N"
    ERROR = "E"
    def __init__(self, port, verbose=False, db_path="atmcontents.json"):
        self.ser = serial.Serial(port, baudrate = 115200)
        self.atm_db = ATM_DB(db_path=db_path)  # figure this out, not sure if it will work
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
        key2 = self.atm_db.admin_get_key("BankKey")
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
            atm_id (str): ID of the ATM
            card_id (str): ID of the ATM card
            pin (str): PIN of ATM card
            amount (str): Requested amount to withdraw

        Returns:
            boolean: True on success
            bool: False on error or failure
        """
        key2 = self.atm_db.admin_get_key("BankKey")
        magic_word1 = self.atm_db.admin_get_key("magicWord1")
        private_key = self.atm_db.admin_get_key("RSAprivate")

        print("bank withdraw")
        self._vp('withdraw: Sending request to Bank')
        hash_magic1 = eh.hash(magic_word1)
        print(len(hash_magic1))
        self.ser.write("a")  # start byte

        self.ser.write(hash_magic1)  # verification, sends hashed version of magicword1 so bank can compare, 32 bytes
        firstHalf = self.spliceSecondHalf(key2)  # split key, and send over first half, 16 bytes
        print(len(firstHalf))
        self.ser.write(firstHalf)

        print("len(AtmId):")  # 36 bytes
        print(len(atm_id))
        print("len(CardId):")  # 36 bytes
        print(len(card_id))
        print("len(Amount):")  # 3 bytes
        print(len(amount))
        print("len(Pin):")  # 8 bytes
        print(len(pin))

        command = "w"  # withdraw
        pkt = SPACING.join([command, atm_id, card_id, amount, pin])  # 1 + 36 + 36 + 3 + 8 + 4 (pad) = 88 bytes
        enc_pkt = eh.aesEncrypt(pkt, key2)  # padded to 96 bytes

        # ///////////////////////////////////////////////////////////////////////////////////////////////////
        # encryption

        print("Packet: %s" % pkt)
        self.ser.write(enc_pkt)  # send
        print("sent")

        tempPacket = ''
        while tempPacket != 'a':
            tempPacket = self.ser.read(1)
            print("looking for packet")

        rec_enc_pkt = self.ser.read(256)  # variable length
        if PADDING in rec_enc_pkt:
            rec_enc_pkt = rec_enc_pkt[:rec_enc_pkt.index(PADDING):]
        rec_dec_pkt = eh.RSA_decrypt(rec_enc_pkt, private_key)

        rec_command, rec_amount, rec_magic_word2 = rec_dec_pkt.split(SPACING)
        print("wait")
        if rec_command == self.GOOD:
            if rec_magic_word2 == self.atm_db.admin_get_key("magicWord2" and rec_amount == amount):  # verification
                self._vp('withdraw: Withdrawal accepted')
                return True
            else:
                return False
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
        return dec_new_magic1  # return to pass to card

    def provision_update(self, uuid, pin, balance):
        pkt = struct.pack(">36s8sI", uuid, pin, balance)
        self.ser.write("p" + pkt)

    def provision_key(self, new_key2, pubkey, magicWord1, magicWord2):
        self.ser.write("a" + new_key2 + pubkey + magicWord1 + magicWord2)  # sends the bank key2, the pub key, and the 2 encrypted magicwords

    def spliceSecondHalf(self, string):
        return string[:len(string)/2]


