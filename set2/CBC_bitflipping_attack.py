import random
import time

from PKCS7 import PKCS7_pad as pad
from PKCS7 import PKCS7_depad as depad
from AES_CBC import Ciphers
from AES_CBC import InvCiphers
from AES_CBC import KeyExpansion

#const
IV = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

randKey = bytes([random.getrandbits(8) for i in range(16)])
w = KeyExpansion( randKey )

def str2bytes( string ):
    return bytes([ord(ltr) for ltr in string])

#first function
def user_input( string ):
    purify = bytes([ltr for ltr in string if ltr != ord(';') and ltr != ord('=')])
    return Ciphers( pad( b'comment1=cooking%20MCs;userdata=' + purify + b';comment2=%20like%20a%20pound%20of%20bacon', 16 ), w, IV )

#second function
def is_admin( cipher ):    
    res = False
    plain = depad( str2bytes(InvCiphers( cipher, w, IV )), 16 )
    if b';admin=true;' in plain:
        res = True
    return res

def XOR_block( block1, block2 ): #16 bytes array
    return bytes([x^y for x,y in zip(block1, block2)])

def main():
    start_time = time.time()
    
    ##  Discover block size and pre + pos's length >>
    feed = b''
    mes = user_input( feed )
    old_len = len(mes)
    changes_count = 0
    counter = 0
    while (1):
        feed += b'\x00'
        counter += 1
        mes = user_input( feed )
        if len(mes) != old_len:
            if changes_count == 0:
                prepos_length = old_len - counter  #len(pre + pos)
            old_len = len(mes)
            changes_count += 1
            if changes_count == 2:
                break
            counter = 0
    block_size = counter
    print('Block size: ' + str(block_size))
    print('Pre-string + Post-string\'s length: ' + str(prepos_length))

    ##  Discover len(pre)
    i = 0
    while user_input(b'')[i:i+16] == user_input(b'\x00')[i:i+16]:
        i += 16

    num = 1
    new_feed = user_input(b'\x00')[i:i+16]
    old_feed = user_input(b'')[i:i+16]
    while new_feed != old_feed:
        num += 1
        old_feed = new_feed
        new_feed = user_input( bytes(num) )[i:i+16]

    pre_pad = num - 1 #bytes(pre_pad + ...) + ...
    pre_length = 16 - pre_pad + i
    pos_length = prepos_length - pre_length

    i += 16 #start of a new block
    
    print('Post-string\'s length:', pos_length)
    
    #Here's the magic: BITFLIPPING ATTACKKKK
    #Note: it's using CBC, not ECB, so we can't find out the pre-string's length anymore
    #So why not call is_admin multiple time and destroy the ciphertext :))

    cipher_admin = str2bytes(user_input(bytes(pre_pad + 16))) #make sure that there will be a plain chunk that is bytes(16)
    wanna_be = b'\x00\x00\x00\x00;admin=true;'
    cipher_admin = cipher_admin[:i-16] + XOR_block(cipher_admin[i-16:i], wanna_be) + cipher_admin[i:]
    
    print('is_admin =', is_admin( cipher_admin ))
    
    #Just a showcase :v not feasible for real life attack    
    plain = depad( str2bytes(InvCiphers( cipher_admin, w, IV )), 16 )
    print(plain)

    elapsed_time = time.time() - start_time
    print('Time elapsed:', elapsed_time)

if __name__ == '__main__':
    main()
