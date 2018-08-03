""" DB
This module implements an interface to the bank_server database.
"""

import json
import os.path
from encryptionHandler import EncryptionHandler
import hashlib
import base64

eh = EncryptionHandler()


class DB(object):
    """Implements a Database interface for the bank server and admin interface"""
    def __init__(self, db_path="bank.json"):
        self.path = db_path

        try:
            with open(db_path, "r") as f:
                d = f.read()
            with open(db_path + ".bak", "w") as f:
                f.write(d)
        except:
            pass

    def close(self):
        """close the database connection"""
        pass

    def init_db(self):
        """initialize database with file at filepath"""
        with open(self.path, 'w') as f:
            f.write(json.dumps({'atms': {}, 'cards': {}}))

    def exists(self):
        return os.path.exists(self.path)

    def modify(self, table, k, subks, vs):
        if not self.exists():
            self.init_db()
        print self.path
        with open(self.path, 'r') as f:
            db = json.loads(f.read())

        try:
            for subk, v in zip(subks, vs):
                if k not in db[table]:
                    print "here"
                    print k
                    db[table][k] = {}
                db[table][k][subk] = v
        except KeyboardInterrupt:
            return False

        with open(self.path, 'w') as f:
            f.write(json.dumps(db))

        return True

    def read(self, table, k, subk):
        with open(self.path, 'r') as f:
            db = json.loads(f.read())

        try:
            print "table: " + table
            print "k: " + k
            print "subk: " + subk
            print db[table]
            print db[table][k]
            print db[table][k][subk]
            return db[table][k][subk]
        except KeyError:
            return None

    ############################
    # BANK INTERFACE FUNCTIONS #
    ############################



    def set_balance(self, card_id, balance):
        """set balance of account: card_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify("cards", card_id, ["bal"], [balance])

    def get_balance(self, account_reference):
        """get balance of account: card_id

        Returns:
            (string or None): Returns balance on Success. None otherwise.
        """
        return self.read("account", account_reference, "bal")

    def get_atm(self, atm_id):
        """get atm_id of atm: atm_id
        this is an obviously dumb function but maybe it can be expanded...

        Returns:
            (string or None): Returns atm_id on Success. None otherwise.
        """
        return 1000
        if self.get_atm_num_bills(atm_id):
            return atm_id
        return None

    def get_key(self, magic):
        return self.read("key", magic, "key")

    def get_atm_num_bills(self, atm_id):
        """get number of bills in atm: atm_id

        Returns:
            (string or None): Returns num_bills on Success. None otherwise.
        """
        return 1000
        print "reading from json with atm_id: " + atm_id
        return self.read("atms", atm_id, "nbills")

    def set_atm_num_bills(self, atm_id, num_bills):
        """set number of bills in atm: atm_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return True
        return self.modify("atms", atm_id, ["nbills"], [num_bills])

    def get_account_id(self, string):
        return self.read("access", string, "account")

    def re_encrypt(self, account_reference, old_key2, new_key2):
        balance = self.get_balance(account_reference)
        balance = eh.aesDecrypt(balance, old_key2)
        account_reference = eh.aesDecrypt(account_reference, old_key2)
        balance = eh.aesEncrypt(balance, new_key2)
        account_reference  = eh.aesEncrypt(account_reference, new_key2)
        return self.modify("account", account_reference, ["bal"], balance)

    #############################
    # ADMIN INTERFACE FUNCTIONS #
    #############################

    def admin_create_account(self, pin, card_id, amount, key2):#pay very close attention here, make sure you get the pin
        """create account with account_name, card_id, and amount

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        hashed_pin = eh.hash(pin)
        hashed_card_id = eh.hash(card_id)
        total_hash = hashed_pin + hashed_card_id
        final_hash = eh.hash(total_hash)#this is now the sensitive info, card and pin are used to create it, but very hard to backtrace,
        final_hash = eh.aesEncrypt(final_hash,key2)#encrypt sensitive info
        # final_hash = "asd"
        # enc_amount = amount
        enc_amount = eh.aesEncrypt(str(amount), key2)#encrypt balance

        return self.modify('accountdata', final_hash, ["bal"], [str(enc_amount)])

    def admin_create_reference(self, pin, card_id, key2):#creates a way to access the account name/reference it
        print pin
        hashed_pin = eh.hash(pin)
        print hashed_pin
        hashed_card_id = eh.hash(card_id)

        total_hash = hashed_pin + hashed_card_id
        final_hash = eh.hash(total_hash)  # this is now the sensitive info, card and pin are used to create it, but very hard to backtrace,
        print final_hash
        final_hash = eh.aesEncrypt(final_hash, key2)  # encrypt sensitive info
        return self.modify("access", "access", ["account1"], [final_hash])

    def admin_create_atm(self, atm_id):# I don't like this
        """create atm with atm_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """

        return self.modify("atms", atm_id, ["nbills"], [128])

    def admin_get_balance(self, card_id):
        """get balance of account: card_id

        Returns:
            (string or None): Returns balance on Success. None otherwise.
        """
        return self.read("cards", card_id, "bal")

    def admin_set_balance(self, card_id, balance):
        """set balance of account: card_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify("cards", card_id, ["bal"], [balance])

    def admin_set_keys(self, key, label):
        #magic is just used to look up the key
        key = base64.b64encode(key)
        return self.modify("keys", "keys", [label], [key])


    def admin_get_key(self, label):
        key = self.read("keys", "keys", label)
        return base64.b64decode(key)


