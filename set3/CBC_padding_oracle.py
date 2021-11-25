import base64
import random
import time

from PKCS7 import valid_pad
from PKCS7 import PKCS7_pad as pad
from AES_CBC import Ciphers
from AES_CBC import InvCiphers
from AES_CBC import KeyExpansion

#const
randKey = bytes([random.getrandbits(8) for i in range(16)])
w = KeyExpansion( randKey )
IV = ''.join([chr(random.getrandbits(8)) for i in range(16)])

#The attacker have control of the ciphertext, IV and the padding_oracle
def str2bytes( string ):
    return bytes([ord(ltr) for ltr in string])

def random_CBC_cipher():
    f = open('17.txt', 'r')
    num = random.randint(1,10)
    count = 0
    for line in f:
        count += 1
        if count == num:
            break
    line = line.replace('\n','').encode('ascii')
    line = base64.b64decode( line )
    print(line)
    
    i = 0
    track_num = ''
    while len(track_num) != len(line):
        track_num += hex(i).replace('0x','')
        i = (i+1) % 16
    print('  ' + track_num)
    print('==== This part is just for debugging, real program down here ↓↓↓ ====\n')
    
    cipher = str2bytes(Ciphers( pad(line, 16), w, IV ))
    return cipher

def padding_oracle( cipher ):
    return valid_pad( str2bytes(InvCiphers( cipher, w, IV )), 16 )
#>> In one of my first trials at this challenge,
#>> my valid_pad return 'True' for '\x00' padding also LOL

def XOR( block1, block2 ):
    return bytes([x^y for x,y in zip(block1, block2)])

def padOf( num ):
    return bytes([num for i in range(num)])

def main():
    cipher = random_CBC_cipher()
    print('cipher:', cipher)
    print('IV:', str2bytes(IV), end = '\n\n')
    print('This is all you have (and a padding_oracle, of course!). Now cracking the cipher...')

    ##  Inner mechanism  >>
    plain = b''

    C2 = str2bytes(IV)

    print('cipher\'s length: ' + str(len(cipher)))
    for t in range(0, len(cipher), 16):
        print('\n\n****  BLOCK NO.' + str(t//16) + '  ****')
        
        C1 = C2
        C2 = cipher[t:t+16]
        
        original_C1 = C1

        DC2 = b'' #decrypted ciphertext

        #so I have to take care of the first two rounds because this attack relies on the
        #hope that first round will make P1+P2 has a valid padding ('\x01')
        #but it could also be ('\x02\x02', '\x03\x03\x03', &c)
        #so only the second round need Loop_detection_agent

        #   NOTE: THE LINE 'decoded P1 + P2: '... IS USED JUST FOR DEBUGGING PURPOSE
        
        #first round
        print('FIRST ROUND >>')
        wanted_C1 = []
        for i in range(256):
            if padding_oracle( C1 + C2 ):
                wanted_C1 += [C1]
                DC2 = bytes([C1[15] ^ 1]) + DC2
                print( XOR(original_C1[15:], DC2) )
                print( str2bytes('decoded P1 + P2: ' + InvCiphers( C1 + C2, w, IV )) )
            C1 = C1[:15] + bytes([(C1[15] + 1) % 256])

        #second round
        for C1 in wanted_C1:
            DC2 = bytes([C1[15] ^ 1]) + DC2
            
            print('\nSECOND ROUND >>')
            looped = False
            C1 = C1[:15] + XOR(DC2, b'\x02')
            loop_count = 0
            while not padding_oracle( C1 + C2 ):
                C1 = C1[:14] + bytes([(C1[14]+1) % 256]) + C1[15:]
                if C1[14] == 0:
                    loop_count += 1
                    if loop_count >= 2:
                        looped = True
                        break
            DC2 = bytes([C1[14] ^ 2]) + DC2
            print( XOR(original_C1[14:], DC2) )
            print( str2bytes('decoded P1 + P2: ' + InvCiphers( C1 + C2, w, IV )) )
            if looped == False:
                break

        #latter rounds
        print('\nLATTER ROUNDS >>')
        for i in range(13,-1,-1):
            C1 = C1[:i+1] + XOR(DC2, padOf(16-i)[1:])
            while not padding_oracle( C1 + C2 ):
                C1 = C1[:i] + bytes([(C1[i]+1) % 256]) + C1[i+1:]
            DC2 = bytes([C1[i] ^ (16-i)]) + DC2
            print( XOR(original_C1[i:], DC2) )
            print( str2bytes('decoded P1 + P2: ' + InvCiphers( C1 + C2, w, IV )) )

        plain += XOR(original_C1, DC2)

    print(plain)
    
if __name__ == '__main__':
    main()
