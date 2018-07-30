"""Backend of ATM interface for xmlrpc"""

import logging
import struct
import serial


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
        pkt = "b" + struct.pack(">36s36s", atm_id, card_id)
        self.ser.write(pkt)

        while pkt not in "ONE":
	    print("check balance 2.0")
            pkt = self.ser.read()
	    print("check balance 2.2")
        if pkt != "O":
	    print("check balance2.5")
            return False
        pkt = self.ser.read(76)
	print("check balance 3")
        aid, cid, bal = struct.unpack(">36s36sI", pkt)
	print("check balance 4")
        self._vp('check_balance: returning balance')
	print("checkbalance 5")
        return bal

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
        pkt = "w" + struct.pack(">36s36sI", atm_id, card_id, amount)
	print("bank withdraw2.5")
        self.ser.write(pkt)
	print("bank withdraw2.75")
        while pkt not in "ONE":
	    print("bank withdraw2.8125")
            pkt = self.ser.read()
	    print(pkt)
	print("bank withdraw2.875")
	print("bank withdraw3")
        if pkt != "O":
	    print("withdraw3.5")
            self._vp('withdraw: request denied')
            return False
	print("bank withdraw4")
        pkt = self.ser.read(72)
        aid, cid = struct.unpack(">36s36s", pkt)
        self._vp('withdraw: Withdrawal accepted')
        return True

    def provision_update(self, uuid, pin, balance):
        pkt = struct.pack(">36s8sI", uuid, pin, balance)
        self.ser.write("p" + pkt)
