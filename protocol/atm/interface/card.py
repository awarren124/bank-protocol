import logging
import struct
import time
import serial
import os
from encryptionHandlerInterface import EncryptionHandlerInterface

eh = EncryptionHandlerInterface()

"""TODO: MAKE KEYS STORED IN A JSON FILE"""
"""TEMPORARRRYYYYY"""
key1 = b'\xe6R|\x84x\xce\x96\xa5T\xac\xd8l\xd0\xe4Lf\xf6&\x16E\xfa/\x9b\xa2\xea!\xceY\x85\xbe\ra'
key2 = b'\xb5\xd2\x03v\xad)\xd5\x8a \xa6\xa0_\x94^\xe6X=$&|&\xd4c*#M\xee[\tl\xfc\xd0'

"""~~~~~~~~~~~~~~~~~"""
PAD = '_'


class NotProvisioned(Exception):
    pass


class AlreadyProvisioned(Exception):
    pass


class Card(object):
    """Interface for communicating with the ATM card

    Args:
        port (str, optional): Serial port connected to an ATM card
            Default is dynamic card acquisition
        verbose (bool, optional): Whether to print debug messages
    """
    CHECK_BAL = 1
    WITHDRAW = 2
    CHANGE_PIN = 3
    CHANGE_MAGWORD1 = 4

    def __init__(self, port=None, verbose=False, baudrate=115200, timeout=2):
        self.ser = serial.Serial(port, baudrate, timeout=timeout)
        self.verbose = verbose
        self.aes_key1 = ""
        self.magic_word_1 = ""

    def _vp(self, msg, stream=logging.info):
        """Prints message if verbose was set

        Args:
            msg (str): message to print
            stream (logging function, optional): logging function to call
        """
        if self.verbose:
            stream("card: " + msg)

    @staticmethod
    def _pad_multi_16(array):
        return array

    def _push_msg(self, msg):
        """Sends encoded and formatted message to PSoC

        Args:
            msg (str): message to be sent to the PSoC
        """
        iv = eh.initializationVector
        eh.regenIV()
        pkt = struct.pack("B%ds" % (len(msg)), len(msg))
        self.ser.write(pkt)
        time.sleep(0.1)

    def _push_msg_enc(self, msg):
        """Sends formatted message to PSoC

        Args:
            msg (str): message to be sent to the PSoC
        """
        enc_msg = eh.aesEncrypt(msg, self.aes_key1)
        iv = eh.initializationVector
        eh.regenIV()
        # pkt = struct.pack("16s%ds" % (len(enc_msg)), iv, enc_msg)  #
        pkt = struct.pack("B16s48s", 64, iv, enc_msg)  # 16 byte iv, 48 byte ciphertext
        self.ser.write(pkt)
        time.sleep(0.1)

    def _pull_msg(self):
        """Pulls message from the PSoC and decodes

        Returns:
            string with message from PSoC
        """
        hdr = self.ser.read(1)
        if len(hdr) != 1:
            self._vp("RECEIVED BAD HEADER: \'%s\'" % hdr, logging.error)
            return ''
        pkt_len = struct.unpack('B', hdr)[0]
        pkt = self.ser.read(pkt_len)
        return pkt

    def _pull_msg_enc(self):
        """Pulls encoded message from the PSoC
            Decodes this message

        Returns:
            string with message from PSoC
        """
        hdr = self.ser.read(1)
        if len(hdr) != 1:
            self._vp("RECEIVED BAD HEADER: \'%s\'" % hdr, logging.error)
            return ''

        pkt_len = struct.unpack('B', hdr)[0]
        iv = self.ser.read(16)

        ciphertext_size = pkt_len - 16
        ciphertext = self.ser.read(ciphertext_size)

        eh.initializationVector = iv

        dec_pkt = eh.aesDecrypt(ciphertext, self.aes_key1)
        pad_start = len(dec_pkt)
        if PAD in dec_pkt:
            pad_start = dec_pkt.index(PAD)
        dec_pkt = dec_pkt[:pad_start:]
        return dec_pkt

    def _sync(self, provision):
        """Synchronize communication with PSoC

        Raises:
            NotProvisioned if PSoC is unexpectedly unprovisioned
            AlreadyProvisioned if PSoC is unexpectedly already provisioned
        """
        if provision:
            if not self._sync_once(["CARD_P"]):
                self._vp("Already provisioned!", logging.error)
                raise AlreadyProvisioned
        else:
            if not self._sync_once(["CARD_N"]):
                self._vp("Not yet provisioned!", logging.error)
                raise NotProvisioned
        self._push_msg("GO\00")
        self._vp("Connection synced")

    def _sync_once(self, names):
        resp = ''
        while resp not in names:
            self._vp('Sending ready message')
            self._push_msg("READY\00")
            resp = self._pull_msg()
            self._vp('Got response \'%s\', want something from \'%s\'' % (resp, str(names)))

            # if in wrong state (provisioning/normal)
            if len(names) == 1 and resp != names[0] and resp[:-1] == names[0][:-1]:
                return False

        return resp

    def _authenticate(self, pin):
        """Requests authentication from the ATM card

        Args:
            pin (str): Challenge PIN

        Returns:
            bool: True if ATM card verified authentication, False otherwise
        """
        self._vp('Sending pin %s' % pin)
        self._push_msg_enc(pin)

        resp = self._pull_msg_enc()
        self._vp('Card response was %s' % resp)
        return resp == 'OK'

    def _get_card_id(self):
        """Retrieves the card_id from the card

        Returns:
            str: card_id of card
        """
        card_id = self._pull_msg_enc()

        self._vp('Card sent card ID %s' % card_id)
        return card_id

    def _send_op(self, op):
        """Sends requested operation to ATM card

        Args:
            op (int): Operation to send from [self.CHECK_BAL, self.WITHDRAW,
                self.CHANGE_PIN]
        """
        self._vp('Sending op %d' % op)
        self._push_msg(str(op))

        while self._pull_msg() != 'K':
            self._vp('Card hasn\'t received op', logging.error)
        self._vp('Card received op')

    def _auth_send_op(self, pin, op):
        """Sends encrypted PIN and operation to ATM card.
            Returns Card ID
            Only works with withdraw or check balance

        Args:
            pin (string): Inputted PIN to send
            op (int): Operation to send

        """
        assert(1 <= op <= 2)
        self._vp('Sending pin %s and op %d' % (pin, op))
        new_key1 = os.urandom(32)
        message = "%s%d%s" % (pin, op, new_key1)  # 8 byte pin, 1 byte op, 32 byte key1
        self._push_msg_enc(message)

        resp = self._pull_msg_enc()
        if resp[-32::] == eh.hash(self.magic_word_1):
            self._vp('Card response good, card received op')
            self.aes_key1 = new_key1
            card_id = resp[:36:]
            return True, card_id
        return False, "", ""


    def _send_new_mword1(self, new_mword1, op):
    	assert(op == 4)
    	message = "%s%d" % (new_mword1, op)
    	self._push_msg_enc(message)

    	return True


    def change_pin(self, old_pin, new_pin):
        """Requests for a pin to be changed

        Args:
            old_pin (str): Challenge PIN
            new_pin (str): New PIN to change to

        Returns:
            bool: True if PIN was changed, False otherwise
        """
        self._sync(False)

        if not self._authenticate(old_pin):
            return False

        self._send_op(self.CHANGE_PIN)

        self._vp('Sending PIN %s' % new_pin)
        self._push_msg(new_pin)

        resp = self._pull_msg()
        self._vp('Card sent response %s' % resp)
        return resp == 'SUCCESS'

    def check_balance(self, pin):
        """Requests for a balance to be checked

        Args:
            pin (str): Challenge PIN

        Returns:
            str: Card id of ATM card on success
            bool: False if PIN didn't match
        """
        self._sync(False)
        '''
        if not self._authenticate(pin):
            return False

        self._send_op(self.CHECK_BAL)
        '''
        response, card_id, card_hash = self._auth_send_op(pin, self.CHECK_BAL)
        if not response:
            return False
        # return self._get_card_id()
        return card_id, card_hash

    def withdraw(self, pin):
        """Requests to withdraw from ATM

        Args:
            pin (str): Challenge PIN

        Returns:
            str: Card id of card on success
            bool: False if PIN didn't match
        """
        self._sync(False)
        '''
        /*
        if not self._authenticate(pin):
            return False
        
        self._send_op(self.WITHDRAW)
        '''
        response, card_id, card_hash = self._auth_send_op(pin, self.WITHDRAW)
        if not response:
            return False
        
        # return self._get_card_id()
        return card_id, card_hash

    def provision(self, card_id, pin, aes_key1, mag_word_1):
        """Attempts to provision a new ATM card

        Args:
            card_id (str): New Card ID for ATM card
            pin (str): Initial PIN for ATM card
            aes_key1 (bytes): initial AES Key 1
            mag_word_1 (str): Magic Word 1

        Returns:
            bool: True if provisioning succeeded, False otherwise
        """
        self._sync(True)
        self.aes_key1 = aes_key1
        self.magic_word_1 = mag_word_1

        msg = self._pull_msg()
        if msg != 'P':
            self._vp('Card already provisioned!', logging.error)
            return False
        self._vp('Card sent provisioning message')

        self._push_msg('%s\00' % pin)
        while self._pull_msg() != 'K':
            self._vp('Card hasn\'t accepted PIN', logging.error)
        self._vp('Card accepted PIN')

        self._push_msg('%s\00' % card_id)
        while self._pull_msg() != 'K':
            self._vp('Card hasn\'t accepted Card ID, logging.error')
        self._vp('Card accepted Card ID')

        self._push_msg('%s\00' % aes_key1)
        while self._pull_msg() != 'K':
            self._vp('Card hasn\'t accepted AES Key 1', logging.error)
        self._vp('Card accepted AES Key 1')

        self._push_msg('%s\00' % mag_word_1)
        while self._pull_msg() != 'K':
            self._vp('Card hasn\'t accepted Magic Word 1', logging.error)
        self._vp('Card accepted Magic Word 1')

        self._vp('Provisioning complete')
        return True
