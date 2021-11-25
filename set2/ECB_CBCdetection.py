import random

from copy import deepcopy

from PKCS7 import PKCS7_pad as pad
from PKCS7 import PKCS7_depad as depad
from AES_ECB import KeyExpansion
from AES_ECB import Ciphers as ECB_Ciphers
from AES_CBC import Cipher
from AES_CBC import XOR

def getMessage():
    f = open('11.txt', 'r', encoding = 'utf-8')
    mes = ''
    for line in f:
        mes += line.replace('\n', '')
    return mes.encode('utf-8')

def getRand16Chrs():
    rand = ''
    rand_arr = [random.getrandbits(8) for i in range(16)]
    for byte in rand_arr:
        rand += chr(byte)
    return rand

def getRand16Bytes():
    return [random.getrandbits(8) for i in range(16)]
    
def CBC_Ciphers( mes, w ):
    cipher = []
    last_cipher = getRand16Chrs()   #random IV
    
    for i in range(0, len(mes), 16):
        last_cipher = Cipher( XOR( last_cipher, mes[i:i+16] ), w )
        cipher += last_cipher

    return ''.join(cipher)

def randInsert( bytes_ ):
    before = random.randint(5,10)
    after = random.randint(5,10)
    for i in range(before):
        bytes_ = bytes(chr(random.getrandbits(8)), 'utf-8') + bytes_
    for i in range(after):
        bytes_ += bytes(chr(random.getrandbits(8)), 'utf-8')
    return bytes_

def repCount( string ):
    rep = 0
    mes = []
    for i in range(0, len(string), 16):
        overlapped = False
        for sub_strs in mes:
            if string[i:i+16] == sub_strs:
                overlapped = True
                rep += 1
                break
        if not overlapped:
            mes += [string[i:i+16]]
    return rep

#expected repetitions
def exRep( length ):
    m = 256**16
    N = length // 16
    return (N-1)*N / (m*2)

def main():
    key = getRand16Bytes()
    w = KeyExpansion( key )

    plain = pad(randInsert(getMessage()), 16)

    cipher = ''
    choose = random.randint(0,1)    #0 => ECB ; 1 => CBC
    if choose == 0:
        print('It\'s ECB time!!!')
        cipher = ECB_Ciphers(plain, w)
    else:
        print('It\'s CBC!!! Behold, the strongest cryptographic message!!')
        cipher = CBC_Ciphers(plain, w)

    if repCount( cipher ) >= exRep( len(cipher) ):
        print('I think it should be ECB, isn\'t it?')
    else:
        print('Gotcha! Definitely CBC!')
    print(repCount( cipher ))
    print(len(cipher))
    print(exRep(len(cipher)))

if __name__ == '__main__':
    main()
