import sys
import hashlib
import random
import time

from Diffie_Hellman import modexp
from AES_CBC import KeyExpansion
from AES_CBC import Ciphers
from AES_CBC import InvCiphers
from PKCS7 import PKCS7_pad as pad
from PKCS7 import PKCS7_depad as depad

#The conversation between A and B has been interfered by M,
#who tell A and B that their public keys are both p, so that the private key is 0
#(or 1: very unlikely, only when a and b are both randomly be 0

def int2str( num ):
    num = hex(num).replace('0x','')
    while len(num) % 2 != 0:
        num = '0' + num
    return bytes([int(num[i:i+2], 16) for i in range(0, len(num), 2)])

def str2bytes( string ):
    return bytes([ord(ltr) for ltr in string])

def main():
    start_time = time.time()

    #A prepares p,g,a and calculate A
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 5
    a = random.randint(0, p-1)
    A = modexp(g, a, p)

    #A sends p,g,A to M
    #M sends p,g,p to B
    A_from_B = p
    b = random.randint(0, p-1)
    B = modexp(g, b, p)
    s = modexp(A_from_B, b, p)

    #B sends B to M
    #Instead of sending B, M sends p to A
    B_from_A = p
    if s != modexp(B_from_A, a, p):
        print('Session keys don\'t match!')
        sys.exit()

    #Now M can conclude that s = 0
    key = hashlib.sha1(int2str(s)).digest()[:16]
    M_key = hashlib.sha1(int2str(0)).digest()[:16]
    w = KeyExpansion( key )
    M_w = KeyExpansion( M_key )

    #A sends message to M, then M relays this to B
    AB_IV = ''.join([chr(random.getrandbits(8)) for _ in range(16)])
    AB_message = str2bytes( Ciphers(pad(b'Hellooooooooo',16), w, AB_IV) )

    #B sends message to M, then M relays this to A
    BA_IV = ''.join([chr(random.getrandbits(8)) for _ in range(16)])
    BA_message = str2bytes( Ciphers(pad(b'How are you??',16), w, BA_IV) )

    #Decrypt everything from M's viewpoint
    print(depad(str2bytes(InvCiphers(AB_message, M_w, AB_IV)), 16))
    print(depad(str2bytes(InvCiphers(BA_message, M_w, BA_IV)), 16))

    time_elapsed = time.time() - start_time
    print('Time elapsed: ' + str(time_elapsed))

if __name__ == '__main__':
    main()
