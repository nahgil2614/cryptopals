import base64
import time
import random

from AES_CBC import Ciphers
from AES_CBC import KeyExpansion

#const
key = b'YELLOW SUBMARINE'
w = KeyExpansion( key )
IV = ''.join(['\x00' for i in range(16)])

nonce = 0

def getMessage():
    f = open('18.txt', 'r')
    mes = f.read().replace('\n','')
    mes = mes.encode('ascii')
    mes = base64.b64decode( mes )
    return mes

def little_endian_64_bit( num ):
    res = hex(num).replace('0x','').rjust(16,'0')
    return bytes([int(res[i:i+2], 16) for i in range(14,-1,-2)])

def XOR( block1, block2 ):
    return bytes([x^y for x,y in zip(block1,block2)])

def str2bytes( string ):
    return bytes([ord(ltr) for ltr in string])

def keystream( nonce_, block_num, w_, IV_ ):
    return str2bytes(Ciphers( little_endian_64_bit(nonce_) + little_endian_64_bit(block_num), w_, IV_ ))

#enter plain, spit out cipher ; enter cipher, spit out plain
def CTR( string, nonce_, w_, IV_ ):
    res = b''
    
    for i in range(0, len(string), 16):
        res += XOR(string[i:i+16], keystream(nonce_, i//16, w_, IV_))

    return res

def main():
    cipher = getMessage()

    ##  Spirit of CTR - encryption is identical to decryption
    plain = CTR(cipher, nonce, w, IV)
    print(plain)
    cipher = CTR(plain, nonce, w, IV)
    print(cipher)
    plain = CTR(cipher, nonce, w, IV)
    print(plain)
    cipher = CTR(plain, nonce, w, IV)
    print(cipher)

if __name__ == '__main__':
    main()
