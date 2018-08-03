import logging
import struct
import time
import serial
from encryptionHandler import EncryptionHandler
eh = EncryptionHandler()



"""TODO: MAKE KEYS STORED IN A JSON FILE"""
"""TEMPORARRRYYYYY"""
key1 = b'\xe6R|\x84x\xce\x96\xa5T\xac\xd8l\xd0\xe4Lf\xf6&\x16E\xfa/\x9b\xa2\xea!\xceY\x85\xbe\ra'
key2 = b'\xb5\xd2\x03v\xad)\xd5\x8a \xa6\xa0_\x94^\xe6X=$&|&\xd4c*#M\xee[\tl\xfc\xd0'

"""~~~~~~~~~~~~~~~~~"""







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

    def __init__(self, port=None, verbose=False, baudrate=115200, timeout=2):
        self.ser = serial.Serial(port, baudrate, timeout=timeout)
        self.verbose = verbose
        self.aes_key1 = ""

    def _vp(self, msg, stream=logging.info):
        """Prints message if verbose was set

        Args:
            msg (str): message to print
            stream (logging function, optional): logging function to call
        """
        if self.verbose:
            stream("card: " + msg)

    def _push_msg(self, msg):
        """Sends encoded and formatted message to PSoC

        Args:
            msg (str): message to be sent to the PSoC
        """
        iv = eh.initializationVector
        eh.regenerateIV()
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
        eh.regenerateIV()
        pkt = struct.pack("B%dsB16s" % (len(msg)), len(msg), enc_msg, 16, iv)
        self.ser.write(pkt)
        time.sleep(0.1)

    def _pull_msg(self):
        """Pulls message from the PSoC

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
        enc_pkt = self.ser.read(pkt_len)

        hdr2 = self.ser.read(1)
        iv_len = struct.unpack('B', hdr2)[0]
        iv = self.ser.read(iv_len)

        eh.initializationVector = iv

        dec_pkt = eh.aesDecrypt(enc_pkt, key1)
        return enc_pkt

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
        self._push_msg(pin)

        resp = self._pull_msg()
        self._vp('Card response was %s' % resp)
        return resp == 'OK'

    def _get_cardID(self):
        """Retrieves the cardID from the ATM card

        Returns:
            str: cardID of ATM card
        """
        cardID = self._pull_msg()#key1) 
        #decrypt

        #eh.aesDecrypt()

        self._vp('Card sent cardID %s' % cardID)
        return cardID

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
            str: cardID of ATM card on success
            bool: False if PIN didn't match
        """
        self._sync(False)

        if not self._authenticate(pin):
            return False

        self._send_op(self.CHECK_BAL)

        return self._get_cardID()

    def withdraw(self, pin):
        """Requests to withdraw from ATM

        Args:
            pin (str): Challenge PIN

        Returns:
            str: cardID of ATM card on success
            bool: False if PIN didn't match
        """
        self._sync(False)

        if not self._authenticate(pin):
            return False

        self._send_op(self.WITHDRAW)

        return self._get_cardID()

    def provision(self, cardID, pin, aes_key1, exp_date, mag_word_1):
        """Attempts to provision a new ATM card

        Args:
            cardID (str): New cardID for ATM card
            pin (str): Initial PIN for ATM card

        Returns:
            bool: True if provisioning succeeded, False otherwise
        """
        self._sync(True)
        self.aes_key1 = aes_key1

        msg = self._pull_msg()
        if msg != 'P':
            self._vp('Card already provisioned!', logging.error)
            return False
        self._vp('Card sent provisioning message')

        self._push_msg('%s\00' % pin)
        while self._pull_msg() != 'K':
            self._vp('Card hasn\'t accepted PIN', logging.error)
        self._vp('Card accepted PIN')

        self._push_msg('%s\00' % cardID)
        while self._pull_msg() != 'K':
            self._vp('Card hasn\'t accepted cardID', logging.error)
        self._vp('Card accepted cardID')

        self._push_msg('%s\00' % aes_key1)
        while self._pull_msg() != 'K':
            self._vp('Card hasn\'t accepted AES Key 1', logging.error)
        self._vp('Card accepted AES Key 1')

        self._push_msg('%s\00' % exp_date)
        while self._pull_msg() != 'K':
            self._vp('Card hasn\'t accepted expiration date', logging.error)
        self._vp('Card accepted expiration date')

        self._push_msg('%s\00' % mag_word_1)
        while self._pull_msg() != 'K':
            self._vp('Card hasn\'t accepted Magic Word 1', logging.error)
        self._vp('Card accepted Magic Word 1')

        self._vp('Provisioning complete')
        return True
