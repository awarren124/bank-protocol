from interface.card import Card
from interface.bank import Bank
from encryptionHandler import EncryptionHandler
from interface.atm_db import ATM_DB

import argparse
import os
import rsa

eh = EncryptionHandler()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("balance", type=int, default=500,
                        help="Starting balance for account")
    parser.add_argument("cport", help="Serial port to the card")
    parser.add_argument("bport", help="Serial port to the bank")
    parser.add_argument("--cbaud", type=int, default=115200,
                        help="Baudrate of serial connection to the card")
    parser.add_argument("--bbaud", type=int, default=115200,
                        help="Baudrate of serial connection to the bank")
    parser.add_argument("--pin", default="12345678",
                        help="Initial pin to program (default 12345678)")
    args = parser.parse_args()
    return args.balance, args.cport, args.bport, args.cbaud, args.bbaud, args.pin


if __name__ == "__main__":
    balance, c_port, b_port, c_baud, b_baud, pin = parse_args()

    # provision card
    print "Creating card object..."
    card = Card(c_port, baudrate=c_baud, verbose=True)
    card_id = os.urandom(18).encode("hex")
    print "Card object created!"

    bank = Bank(b_port)
    print "Linked to bank!"

    # =====MARK=========#
    # bank.provision_update("c0573011d92ce40c8b5dbfa73025b352c899", pin, balance)
    # print "Provisioning successful"

    key1 = os.urandom(32)  # starts by generating all keys for creation of the account, key1 used between card and atm
    key2 = os.urandom(32)  # key2 is the key specifically used btwn bank and atm

    magicWord1 = os.urandom(32)  # verification words, stored by both atm and bank upon creation
    magicWord2 = os.urandom(32)  # verification words, stored by both atm and bank upon creation

    print "creating RSA key pair!"
    test_n = int('27928727520532098560054510086934803266769027328779773633\
51762493251995978285544035350906266382585272722398629867\
67263282027760422651274751164233304322779357458680526177\
93594651686619933029730312573799176384081348734718092523\
53476550057243981913102899068449856388885987417785575633\
66522578044678796800808595716146657069948593436088106761\
86674067708949755093039975941211253008157978789036441127\
01109572656021257137086334620169063315388954284609394192\
32250643688514600699603929824545296848370051254650037973\
10139479221307918200583851065828489354285517184240655579\
549337386740031302249496379882799360098372401884741329801')
    test_p = int('17791143933509595918127954499653383601218835098160342274\
21719349464132778400846891474457120589082133325302604179\
82181001327467441044697854896458761089076165690493808885\
78606941384914032562858753139200694087767527290102835209\
36343115102676302117059691295229400834867089684114302209\
27632138221540171427701495839')
    test_q = int('15698106667513592225651910118661853088086996081175911345\
49581990193390503622003253143718326860723480921952218366\
69795595987275285870475032000847646645415387334949112223\
81409068648841957504994872889663428380162653646162371919\
71899699949089072105502530930366392712822832371160724348\
51400420434671809603239292759')
    test_d = int('11694038663517117301470250565262034216448859101409063098362103022312284913885837599228560790973728194573346476371943286574185229348266827054484834679526661806343977171443215753496994637872786815193518519296818229254152603520733593238952169325370013374633769093667305549648512135276776089940223127184660556136159547376416667869896924502423465202741792836040503053603572485582841043345759584648665276599257323452631275501368932097249828765063405475852819534868905659539017714354685090189789726054188709518034193411399471895763029830001463150092121999994638369710990065919332854476908436910190143961401564369877308095445')
    test_pub_key = {
        'e': 65537,
        'n': test_n
    }
    test_priv_key = {
        'n': test_n,
        'e': 65537,
        'd': test_d,
        'p': test_p,
        'q': test_q
    }
    pubkey, privkey = (rsa.PublicKey(**test_pub_key), rsa.PrivateKey(**test_priv_key))  # for testing
    # pubkey, privkey = eh.gen_key_pair()  # RSA key pair, atm stores private, bank stores public

    # rsa.key.AbstractKey.load_pkcs1(key) to retrieve formatted object

    print "finished with RSA key pair!"

    magicWord1 = eh.aesEncrypt(magicWord1, key2)  # encrypt both verification words with key2
    magicWord2 = eh.aesEncrypt(magicWord2, key2)

    atm_db = ATM_DB()  # create atm_db database object

    atm_db.admin_set_key(key1, "CardKey")  # stores key1 in the atm, mapped with string "CardKey" for access
    atm_db.admin_set_key(key2, "BankKey")  # stores key2 in the atm, mapped with string "BankKey" for access

    atm_db.admin_set_key(key1, "magicWord1")  # stores magicWord1 in the atm, mapped with string "magicWord1" for access
    atm_db.admin_set_key(key2, "magicWord2")  # stores magicWord2 in the atm, mapped with string "magicWord2" for access

    atm_db.admin_set_key(pubkey, "RSApublic")  # ditto
    atm_db.admin_set_key(privkey, "RSAprivate")  # ditto

    print "provision lengths:"
    print "AES key 2 length: %s" % len(str(key2))
    print "RSA private key length: %s" % len(pubkey.save_pkcs1())
    print "RSA public key length: %s" % len(privkey.save_pkcs1())
    print "Magic word 1 length: %s" % len(str(magicWord1))
    print "Magic word 2 length: %s" % len(str(magicWord2))

    if card.provision(card_id, pin, key1, magicWord1):  # for general purposes, ignore
        print "Card provisioned!"

        # update bank
        print "Updating bank..."
        bank.provision_update(card_id, pin, balance)
        print "Provisioning successful"
    else:
        print "Card already provisioned!"

    bank.provision_key(key2, pubkey, magicWord1, magicWord2)  # run provision key in /atm/interface/bank,
    print "keys sent"

    '''
    if card.provision(card_id, pin, key1, magicWord1):  # for general purposes, ignore
        print "Card provisioned!"

        # update bank
        print "Updating bank..."
        bank = Bank(b_port)
        bank.provision_update(card_id, pin, balance)
        print "Provisioning successful"
    else:
        print "Card already provisioned!"
    '''
