"""Backend of ATM interface for xmlrpc"""

import logging
import struct
import serial
from encryption_handler import EncryptionHandler
from atm_db import atmDB
import Adafruit_BBIO.UART as UART

UART.setup("UART4")
UART.setup("UART1")

eh = EncryptionHandler()
SPACE_CHAR = '+'
PAD_CHAR = '_'


class Bank:
    """Interface for communicating with the bank from the ATM

    Args:
        port (serial.Serial): Port to connect to
    """
    GOOD = "O"
    BAD = "N"
    ERROR = "E"

    def __init__(self, port, verbose=True, db_path="atmcontents.json"):
        self.ser = serial.Serial(port, baudrate = 115200)
        self.atm_db = atmDB(db_path=db_path)  # figure this out, not sure if it will work
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

        key2 = self.atm_db.admin_get_key("BankKey")
        enc_command = eh.aes_encrypt("b", key2)
        enc_atm_id = eh.aes_encrypt(atm_id, key2)
        enc_card_id = eh.aes_encrypt(card_id, key2)
        enc_pkt = enc_command + enc_atm_id + enc_card_id

        self._vp('check_balance: Constructed encoded packet, sending now')
        self.ser.write(enc_pkt)

        # outdated code? Uses struct packing
        """
        pkt = ""
            while pkt not in "ONE":
                pkt = self.ser.read()
            if pkt != "O":
                return False
            pkt = self.ser.read(76)
            # recieved_atm_id, received_card_id, received_bal = struct.unpack(">36s36sI", pkt)
        """

        cmd = ""
        while cmd != 'a':
            cmd = self.ser.read(1)

        self._vp('check_balance: Received response')
        decision = self.ser.read(16)
        dec_decision = eh.aes_decrypt(decision, key2)

        if dec_decision == 'O':
            recieved_atm_id = self.ser.read(48)
            received_card_id = self.ser.read(48)
            received_bal = self.ser.read(16)

            decrypted_atm_id = eh.aes_decrypt(recieved_atm_id, key2)
            decrypted_card_id = eh.aes_decrypt(received_card_id, key2)
            decrypted_bal = eh.aes_decrypt(received_bal, key2)
            self._vp('check_balance: Returning balance')
            return decrypted_bal
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
        magic_word_1 = self.atm_db.admin_get_key("magicWord1")
        private_key = self.atm_db.admin_get_key("RSAprivate")

        self._vp('withdraw: Sending request to Bank')
        hash_magic_1 = eh.hash_to_hex(magic_word_1)

        self.ser.write("a")  # start byte
        self.ser.write(hash_magic_1)  # verification, sends hashed version of magicword1 so bank can compare, 32 bytes
        key2_first_half = self.split_second_half(key2)  # split key, and send over first half, 16 bytes
        self.ser.write(key2_first_half)

        # print lengths for checking purposes
        print "len(AtmId): %s" % len(atm_id)  # 36 bytes
        print "len(CardId): %s" % len(card_id)  # 36 bytes
        print "len(Amount): %s" % len(amount)  # 3 bytes
        print "len(Pin): %s" % len(pin)  # 8 bytes

        # ///////////////////////////////////////////////////////////////////////////////////////////////////
        # encrypt and send packet

        command = "w"  # withdraw
        pkt = SPACE_CHAR.join([command, atm_id, card_id, amount, pin])  # 1 + 36 + 36 + 3 + 8 + 4 (pad) = 88 bytes
        enc_pkt = eh.aes_encrypt(pkt, key2)  # padded to 96 bytes

        print "Packet: %s" % pkt
        self.ser.write(enc_pkt)  # send
        self._vp('withdraw: Sending encrypted packet to Bank')

        temp_header = ''
        while temp_header != 'a':
            temp_header = self.ser.read(1)
            print "looking for packet"

        rec_enc_pkt = self.ser.read(256)  # variable length
        rec_enc_pkt = rec_enc_pkt[:rec_enc_pkt.find(PAD_CHAR):]
        rec_dec_pkt = eh.rsa_decrypt(rec_enc_pkt, private_key)

        rec_command, rec_amount, rec_magic_word2 = rec_dec_pkt.split(SPACE_CHAR)
        print "wait"
        if rec_command == self.GOOD:
            if rec_magic_word2 == self.atm_db.admin_get_key("magicWord2" and rec_amount == amount):  # verification
                self._vp('withdraw: Withdrawal accepted')
                return True
            else:
                return False
        return False

    def regenerate_keys(self, atm_id, card_id):
        private_key = self.atm_db.admin_get_key("RSAprivate")
        command = ''
        while command != 'r':
            command = self.ser.read(1)  # receives everything from bank

        # rec_new_key1 = self.ser.read()
        rec_new_key2 = self.ser.read()
        rec_new_iv = self.ser.read()
        dec_iv = eh.rsa_decrypt(rec_new_iv, private_key)
        eh.iv = dec_iv
        rec_new_magic1 = self.ser.read()  # lengths are unknown !!!!!!
        rec_new_magic2 = self.ser.read()
        ver_magic1 = self.ser.read()
        ver_magic2 = self.ser.read()

        dec_new_key2 = eh.rsa_decrypt(rec_new_key2, private_key)
        dec_new_magic1 = eh.rsa_decrypt(rec_new_magic1, private_key)
        dec_new_magic2 = eh.rsa_decrypt(rec_new_magic2, private_key)
        dec_ver_magic1 = eh.rsa_decrypt(ver_magic1, private_key)
        dec_ver_magic2 = eh.rsa_decrypt(ver_magic2, private_key)

        if dec_ver_magic1 == self.atm_db.admin_get_key("magicWord1") and dec_ver_magic2 == self.atm_db.admin_get_key("magicWord2"):  # check line syntax, checks to verify the bank is the bank
            self.atm_db.admin_set_key(dec_new_key2, "BankKey")  # replaces bank key with new key
            self.atm_db.admin_set_key(dec_new_magic1, "magicWord1")  # replaces magic words
            self.atm_db.admin_set_key(dec_new_magic2, "magicWord2")  # replaces magic words
        return dec_new_magic1  # return to pass to card

    def provision_update(self, uuid, pin, balance):
        pkt = struct.pack(">36s8sI", uuid, pin, balance)
        self.ser.write("p" + pkt)

    def provision_key(self, new_key2, pubkey, magic_word_1, magic_word_2):
        self.ser.write("a" + new_key2 + pubkey + magic_word_1 + magic_word_2)  # sends the bank key2, the pub key, and the 2 encrypted magicwords

    def split_second_half(self, string):
        return string[:len(string)/2]
