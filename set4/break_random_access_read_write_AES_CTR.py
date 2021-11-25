import base64
import time
import sys

from AES_ECB import InvCiphers
from AES_ECB import KeyExpansion

from AES_CTR import CTR
from AES_CTR import XOR
from AES_CTR import keystream

from MT19937 import seed_mt
from MT19937 import extract_number

class ecb:
    key = b'YELLOW SUBMARINE'
    w = KeyExpansion( key )

class ctr:
    seed_mt(int(time.time()))
    key = bytes([extract_number() % 256 for _ in range(16)])
    w = KeyExpansion( key )
    IV = ''.join([chr(extract_number() % 256) for _ in range(16)])
    nonce = (extract_number() << 32) + extract_number() #'random' but constant 64-bit nonce

########################################
    
def str2bytes( string ):
    return bytes([ord(ltr) for ltr in string])

def getPlain():
    f = open('25.txt', 'r')
    mes = ''
    for line in f:
        mes += line.replace('\n','')
    mes = mes.encode('ascii')
    mes = base64.b64decode( mes )
    return str2bytes(InvCiphers( mes, ecb.w ))

def getCipher():
    return CTR( getPlain(), ctr.nonce, ctr.w, ctr.IV )

cipher = getCipher() ##

def edit(ciphertext, key, offset, newtext):
    if key != ctr.key:
        print('Sorry, you don\'t have permission to use this function!')
        sys.exit()
    newcipher = b''
    old_block = offset//16
    trunc_key = keystream(ctr.nonce, offset//16, ctr.w, ctr.IV)
    for i in range(len(newtext)):
        if (i+offset)//16 != old_block:
            old_block = (i+offset)//16
            trunc_key = keystream(ctr.nonce, (i+offset)//16, ctr.w, ctr.IV)
        newcipher += bytes([newtext[i] ^ trunc_key[(i+offset) % 16]])
    return ciphertext[:offset] + newcipher + ciphertext[offset+len(newtext):]

def edit_leaked(offset, newtext):
    return edit(cipher, ctr.key, offset, newtext)

def main():
    start_time = time.time()

    print('The attacker has:')
    print(cipher)

    robbed_key = edit_leaked(0, bytes([0 for _ in range(len(cipher))]))
    print('THE ATTACKER HAS SUCCESSFULLY READ THE PLAINTEXT')
    print(XOR(cipher, robbed_key))

    time_elapsed = time.time() - start_time
    print('Time elapsed: ' + str(time_elapsed))

if __name__ == '__main__':
    main()
