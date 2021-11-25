##  The code in this file is a re-used version of set1/repeatingXORdecoder.py  >>

import base64
import random
import math
import sys
import XORdecoder

from AES_CTR import CTR
from AES_CBC import KeyExpansion

#const
nonce = 0
randKey = bytes([random.getrandbits(8) for i in range(16)])
w = KeyExpansion( randKey )
IV = ''.join([chr(random.getrandbits(8)) for i in range(16)])

def message( base64_message ):
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode( base64_bytes )
    ciphers = message_bytes.decode('ascii')
    return ciphers

def asciiToHex( mes ):
    hex_mes = ''
    for i in mes:
        hex_mes += hex(ord(i)).replace('0x', '').rjust(2, '0')
    return hex_mes

def bytes2str( byte ):
    return ''.join([chr(ltr) for ltr in byte])

def bunch_of_ciphertexts():
    res = []
    f = open('20.txt', 'r')
    for line in f:
        res += [bytes2str(CTR( base64.b64decode(line.replace('\n','').encode('ascii')), nonce, w, IV ))]
    return res

def main():
    ciphers = bunch_of_ciphertexts()

    print('*****  All you have  *****')
    for cipher in ciphers:
        print(cipher)
    
    best_keyl = min([len(cipher) for cipher in ciphers])

    temp = ''
    for cipher in ciphers:
        temp += cipher[:best_keyl]
    ciphers = temp
    
    texts_with_single_char_key = []
    for i in range(best_keyl):
        texts_with_single_char_key += ['']
        for jumping_collector in range(i, len(ciphers), best_keyl):
            texts_with_single_char_key[i] += ciphers[jumping_collector]
        texts_with_single_char_key[i] = XORdecoder.XOR_decode( asciiToHex(texts_with_single_char_key[i]) )

    plain = ''
    for i in range(len(texts_with_single_char_key[0])):
        for j in range(best_keyl):
            if i < len(texts_with_single_char_key[j]):
                plain += texts_with_single_char_key[j][i]

    print('\n*****  And I have decrypted it for you  *****')
    for i in range(0, len(plain), best_keyl):
        print(plain[i:i+best_keyl])            

if __name__ == '__main__':
    main()
