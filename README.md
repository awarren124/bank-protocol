# bank-protocol
    What our code does:

The purpose of our code is to prevent attackers from accessing a users account, balance, PIN, duplicate a card. To access your account the user will need a to insert their card and use their correct PIN. Once the user accesses their account they will not be able to withdraw more money than the amount of money that they have in their balance, but they will be able to withdraw money that is less than or equal to the amount of money in their balance, check their balance, or change their PIN. 


    Sequence Diagram:

   https://tinyurl.com/yd9f8rgr 


    How to use our code:

To use our code the user will insert the card and enter the PIN into the prompted area. If the PIN and Card information is correct, then the user will decide whether they want to withdraw money, change their PIN, or check their balance. If they want to withdraw money, then the user's request will be sent to the bank and the bank will accept or deny their request after confirming that the person requesting the money is the correct user and that the user has enough money in their bank account.

    Implementation details:

When the card, ATM, and bank were first created they were programmed to have certain informtation. The Card will store AES Key 1, the Card ID, the hashed magic word 3, the hashed PIN, and magic word 1 and the expiration date of the card which are concatenated then hashed together. The ATM will have the AES Key , AES Key 2, RSA Public Key 1, RSA Private Key 2, Magic Word 1 and Magic Word 2. The Bank will store the RSA Public Key 1, the second half of the AES KEy 2 see, Magic word 1 encrypted with AES Key 2, Magic word 2 encrypted with AES KEy 2, each accounts balance that is encrypted with AES key 2, and each account that is identified with the hashed pin concatenated with the hashed card ID which is then hashed together and encrypted with the AES key 2 Access string. The creation portion of the code was created to prevent any attackers from pretending to be the bank, card, or atm and getting any of the users information. After each transaction AES KEy 1, AES Key 2, Magic Word 1, and Magic Word 2 are all regenerated.
