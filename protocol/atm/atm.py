import logging
import sys
import cmd
from interface.card_interface import NotProvisioned
from interface import card_interface, bank_interface
import os
import json
import argparse

log = logging.getLogger('')
log.setLevel(logging.DEBUG)
log_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(log_format)
log.addHandler(ch)

"""TODO: MAKE KEYS STORED IN A JSON FILE"""


class ATM(cmd.Cmd, object):
    """Interface for ATM xmlrpc server

    Args:
        bank (Bank or BankEmulator): Interface to bank
        card (Card or CardEmulator): Interface to ATM card
    """
    intro = 'Welcome to your friendly ATM! Press ? for a list of commands\r\n'
    prompt = '1. Check Balance\r\n2. Withdraw\r\n3. Change PIN\r\n> '

    def __init__(self, bank, card, config_path="config.json",
                 billfile="billfile.out", verbose=True):

        super(ATM, self).__init__()
        self.bank = bank
        self.card = card
        self.config_path = config_path
        self.billfile = billfile
        self.verbose = verbose
        cfg = self.config()
        self.atm_id = cfg["atm_id"].decode("hex")  # 36 bytes long
        self.dispensed = int(cfg["dispensed"])
        self.bills = cfg["bills"]
        self.update()

    def _vp(self, msg, log=logging.debug):
        if self.verbose:
            log(msg)

    def config(self):
        if not os.path.isfile(self.config_path):
            cfg = {"atm_id": os.urandom(36).encode('hex'), "dispensed": 0,
                   "bills": ["example bill %5d" % i for i in range(128)]}
            return cfg
        else:
            with open(self.config_path, "r") as f:
                return json.loads(f.read())

    def update(self):
        with open(self.config_path, "w") as f:
            f.write(json.dumps({"atm_id": self.atm_id.encode("hex"), "dispensed": self.dispensed,
                                "bills": self.bills}))

    def check_balance(self, pin):
        """Tries to check the balance of the account associated with the
        connected ATM card

        Args:
            pin (str): 8 digit PIN associated with the connected ATM card

        Returns:
            str: Balance on success
            bool: False on failure
        """
        try:
            self._vp('check_balance: Requesting card_id using inputted pin')
            card_id = self.card.check_balance(pin)

            # get balance from bank if card accepted PIN
            if card_id:
                print("Communicated with card")
                self._vp('check_balance: Requesting balance from Bank')
                res = self.bank.check_balance(self.atm_id, card_id, pin)
                print(res)
                if res:
                    print("balance is: " + str(res))
                    return res
            self._vp('check_balance failed')
            return False
        except NotProvisioned:
            self._vp('ATM card has not been provisioned!')
            return False

    def change_pin(self, old_pin, new_pin):
        """Tries to change the PIN of the connected ATM card

        Args:
            old_pin (str): 8 digit PIN currently associated with the connected
                ATM card
            new_pin (str): 8 digit PIN to associate with the connected ATM card

        Returns:
            bool: True on successful PIN change
            bool: False on failure
        """
        try:
            self._vp('change_pin: Sending PIN change request to card')
            if self.card.change_pin(old_pin, new_pin):
                return True
            self._vp('change_pin failed')
            return False
        except NotProvisioned:
            self._vp('ATM card has not been provisioned!')
            return False

    def withdraw(self, pin, amount):
        """Tries to withdraw money from the account associated with the
        connected ATM card

        Args:
            pin (str): 8 digit PIN currently associated with the connected
                ATM card
            amount (str): number of bills to withdraw

        Returns:
            list of str: Withdrawn bills on success
            bool: False on failure
        """
        try:
            self._vp('withdraw: Requesting card_id from card')
            card_id = self.card.withdraw(pin)  # card interface executes protocol

            if card_id:
                print("Communicated with card")
                self._vp('withdraw: Sending request to bank')

                if self.bank.withdraw(self.atm_id, card_id, pin, amount):  # run withdraw in /interface/bank_interface.py
                    with open(self.billfile, "w") as f:
                        self._vp('withdraw: Dispensing bills...')
                        for i in range(self.dispensed, self.dispensed + int(amount)):
                            f.write(self.bills[i] + "\n")
                            self.bills[i] = "-DISPENSED BILL-"
                            self.dispensed += 1

                    self.update()  # update new dispensed bills
                    new_mword1 = self.bank.regenerate_keys()  # regenerate keys with bank interface, receive new magic word 1
                    if self.card.change_magic_word1(new_mword1):  # send new magic word 1 to card, card interface
                        return True
                else:
                    print 'withdraw from bank failed'
            else:
                self._vp('withdraw failed')
                return False

        except ValueError:
            self._vp('amount must be an int')
            return False
        except NotProvisioned:
            self._vp('ATM card has not been provisioned!')
            return False

    def get_pin(self, prompt="Please insert 8-digit PIN: "):
        pin = ''
        while len(pin) != 8:
            pin = raw_input(prompt)
            if not pin.isdigit():
                print("Please only use digits")
                continue
        return pin

    def do_1(self, args):
        """Check Balance"""
        pin = self.get_pin()
        if not self.check_balance(pin):
            print("Balance lookup failed!")

    def do_2(self, args):
        """Withdraw"""
        pin = self.get_pin()

        amount = 'not correct'
        while not (len(amount) == 3 and amount.isdigit()):
            amount = raw_input("Please enter valid amount to withdraw, 3 digits: ")

        if self.withdraw(pin, amount):
            print("Withdraw success!")
        else:
            print("Withdraw failed!")

    def do_3(self, args):
        """Change PIN"""
        old_pin = self.get_pin()
        new_pin = self.get_pin("Please insert new 8-digit PIN: ")
        if self.change_pin(old_pin, new_pin):
            print("PIN change success!")
        else:
            print("PIN change failed!")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("bankport", help="Serial port connected to the bank")
    parser.add_argument("cardport", help="Serial port connected to the card")
    parser.add_argument("--config", default="config.json",
                        help="Path to the configuration file")
    parser.add_argument("--billfile", default="billfile.out",
                        help="File to print bills to")
    parser.add_argument("--verbose", action="store_true",
                        help="Print verbose debug information")
    args = parser.parse_args()
    return args.bankport, args.cardport, args.config, args.billfile, args.verbose


if __name__ == "__main__":  #
    c_port, b_port, config, billfile, verbose = parse_args()
    bank = bank_interface.Bank(b_port, verbose=verbose)
    card = card_interface.Card(c_port, verbose=verbose)
    atm = ATM(bank, card, config, billfile, verbose=verbose)
    atm.cmdloop()
