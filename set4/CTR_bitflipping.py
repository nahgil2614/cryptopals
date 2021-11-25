import time

from MT19937 import seed_mt
from MT19937 import extract_number

from AES_CBC import KeyExpansion

from AES_CTR import CTR

#const
seed_mt(int(time.time()))
IV = ''.join([chr(extract_number() % 256) for _ in range(16)])
nonce = (extract_number() << 32) + extract_number()

randKey = bytes([extract_number() % 256 for _ in range(16)])
w = KeyExpansion( randKey )

#first function
def user_input( string ):
    purify = bytes([ltr for ltr in string if ltr != ord(';') and ltr != ord('=')])
    return CTR( b'comment1=cooking%20MCs;userdata=' + purify + b';comment2=%20like%20a%20pound%20of%20bacon', nonce, w, IV )

#second function
def is_admin( cipher ):    
    res = False
    plain = CTR( cipher, nonce, w, IV )
    if b';admin=true;' in plain:
        res = True
    return res

def XOR( block1, block2 ):
    return bytes([x^y for x,y in zip(block1, block2)])

def main():
    start_time = time.time()
    
    wanna_be = b';admin=true;'
    test = user_input(b'A')
    cipher = user_input(bytes(len(wanna_be)))
    i = 0
    while test[i] == cipher[i]:
        i += 1
    cipher_admin = cipher[:i] + XOR(cipher[i:i+len(wanna_be)], wanna_be) + cipher[i+len(wanna_be):]
    print('is_admin = ' + str(is_admin(cipher_admin)))

    elapsed_time = time.time() - start_time
    print('Time elapsed:', elapsed_time)

if __name__ == '__main__':
    main()
