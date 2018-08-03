""" DB
This module implements an interface to the bank_server database.
"""

import json
import os.path
from encryptionHandler import EncryptionHandler
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
        with open(self.path, 'r') as f:
            db = json.loads(f.read())

        try:
            for subk, v in zip(subks, vs):
                if k not in db[table]:
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

    #############################
    # ADMIN INTERFACE FUNCTIONS #
    #############################

    def admin_create_account(self, pin, card_id, amount, key2):#pay very close attention here, make sure you get the pin
        """create account with account_name, card_id, and amount

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        hashed_pin = hash(pin)
        hashed_card_id = hash(card_id)
        total_hash = hashed_pin + hashed_card_id
        final_hash = hash(total_hash)#this is now the sensitive info, card and pin are used to create it, but very hard to backtrace,
        final_hash = eh.aesEncrypt(final_hash,key2)#encrypt sensitive info
        amount = eh.aesEncrypt(amount, key2)#encrypt balance
        return self.modify('account', final_hash, ["bal"], [amount])

    def admin_create_reference(self, pin, card_id, key2):#creates a way to access the account name/reference it
        hashed_pin = hash(pin)
        hashed_card_id = hash(card_id)
        total_hash = hashed_pin + hashed_card_id
        final_hash = hash(total_hash)  # this is now the sensitive info, card and pin are used to create it, but very hard to backtrace,
        final_hash = eh.aesEncrypt(final_hash, key2)  # encrypt sensitive info
        return self.modify("access", "access", "account", final_hash)

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

    def admin_set_keys(self, key, magic):
        #magic is just used to look up the key
        return self.modify("key", magic, ["key"], [key)


    def admin_get_key(self, key, magic):
        return self.read("key", magic, "key")


