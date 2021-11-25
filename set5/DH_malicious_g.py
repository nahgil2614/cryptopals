import sys
import hashlib
import random
import time

from AES_CBC import KeyExpansion
from AES_CBC import Ciphers
from AES_CBC import InvCiphers
from PKCS7 import PKCS7_pad as pad
from XORdecoder import English_score

def depad( mes, block_size ):
    res = mes
    if len(mes) % block_size != 0:
        res = b'\x00'
    else:
        num = mes[-1]
        for i in range(num):
            if res[-1] != num:
                res = b'\x00'
                break
            res = res[:-1]
    return res

def modexp(A, b, c): #return A**b mod c
    x = A
    R = 1
    while b != 0:
        if b & 1:
            R = (R * x) % c
        b >>= 1
        x = (x * x) % c
    return R

def int2str( num ):
    num = hex(num).replace('0x','')
    while len(num) % 2 != 0:
        num = '0' + num
    return bytes([int(num[i:i+2], 16) for i in range(0, len(num), 2)])

def str2bytes( string ):
    return bytes([ord(ltr) for ltr in string])

def bytes2str( byte ):
    return ''.join([chr(num) for num in byte])

def main():
    start_time = time.time()

    #########################################################################
    print('*********  THE COMMON SCENARIO WITH NO MITM  *********')
    
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2

    print('\nAlice sends p,g to Bob...')
    print('p = ' + hex(p))
    print('g = ' + hex(g))

    print('\nBob sends back ACK...')
          
    ###  Alice  >>>
    a = random.randint(0, p-1)
    A = modexp(g, a, p)
    print('\nAlice sends Bob A = ' + hex(A))

    ###  Bob  >>>
    b = random.randint(0, p-1)
    B = modexp(g, b, p)
    print('\nBob sends Alice B = ' + hex(B))

    ###  Exchange their public keys (A and B) and calculate their session key  >>>
    # Alice sends confirmation message to make sure that they came up with the same session key
    msg = b'some dummy test message'
    s_a = modexp(B, a, p)
    key_a = hashlib.sha1( int2str(s_a) ).digest()[:16]
    w_a = KeyExpansion( key_a )
    iv = ''.join([chr(random.getrandbits(8)) for _ in range(16)])
    send_ab = str2bytes( Ciphers(pad(msg, 16), w_a, iv) )
    print('\nAlice sends Bob confirmation message: ' + str(send_ab))
    print('and the random iv used: ' + str(str2bytes(iv)))

    # Bob decodes that and encodes again the message with his session key and iv
    s_b = modexp(A, b, p)
    key_b = hashlib.sha1( int2str(s_b) ).digest()[:16]
    w_b = KeyExpansion( key_b )
    msg_rcv = depad(str2bytes(InvCiphers( send_ab, w_b, iv )), 16)
    iv = ''.join([chr(random.getrandbits(8)) for _ in range(16)])
    send_ba = str2bytes( Ciphers( pad(msg_rcv, 16), w_b, iv ) )
    print('\nBob sends back his comfirmation message: ' + str(send_ba))
    print('with the random iv used: ' + str(str2bytes(iv)))

    # Alice decodes and make sure that Bob has the same session key as her
    send_ba_decoded = depad( str2bytes(InvCiphers( send_ba, w_a, iv )), 16 )
    if send_ba_decoded == msg:
        print('\nOkay, Bob. I know you\'re there!')
    else:
        print('\nOh oh. Is that you, Bob? Or you\'re the hacker??')

    #########################################################################
    print('\n\n*********  MITM IN ACTION _ g = 1  *********')
    
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2

    print('\nAlice sends p,g to M...')
    print('p = ' + hex(p))
    print('g = ' + hex(g))

    print('M sends p and the malicious g = 1 to Bob...')
    g_b = 1
    print('p = ' + hex(p))
    print('g = ' + hex(g_b))
    
    print('\nBob sends back ACK to M, then M forwards that to Alice...')
          
    ###  Alice  >>>
    a = random.randint(0, p-1)
    A = modexp(g, a, p)
    print('\nAlice sends M A = ' + hex(A))

    print('M sends A = 1 to Bob...')
    A_b = 1

    ###  Bob  >>>
    b = random.randint(0, p-1)
    B = modexp(g_b, b, p)
    print('\nBob sends M B = ' + hex(B))
    print('M forwards that to Alice')

    ###  Exchange their public keys (A and B) and calculate their session key  >>>
    # Alice sends confirmation message to make sure that they came up with the same session key
    msg = b'some dummy test message'
    s_a = modexp(B, a, p)
    key_a = hashlib.sha1( int2str(s_a) ).digest()[:16]
    w_a = KeyExpansion( key_a )
    iv = ''.join([chr(random.getrandbits(8)) for _ in range(16)])
    send_ab = str2bytes( Ciphers(pad(msg, 16), w_a, iv) )
    print('\nAlice sends Bob confirmation message: ' + str(send_ab))
    print('and the random iv used: ' + str(str2bytes(iv)))

    # Bob decodes that and encodes again the message with his session key and iv
    s_b = modexp(A_b, b, p)
    key_b = hashlib.sha1( int2str(s_b) ).digest()[:16]
    w_b = KeyExpansion( key_b )
    msg_rcv = depad(str2bytes(InvCiphers( send_ab, w_b, iv )), 16)
    iv = ''.join([chr(random.getrandbits(8)) for _ in range(16)])
    send_ba = str2bytes( Ciphers( pad(msg_rcv, 16), w_b, iv ) )
    print('\nBob sends back his comfirmation message: ' + str(send_ba))
    print('with the random iv used: ' + str(str2bytes(iv)))

    # Alice decodes and make sure that Bob has the same session key as her
    send_ba_decoded = depad( str2bytes(InvCiphers( send_ba, w_a, iv )), 16 )
    if send_ba_decoded == msg:
        print('\nOkay, Bob. I know you\'re there!')
    else:
        print('\nOh oh. Is that you, Bob? Or you\'re the hacker??')
        sys.exit()

    print('\nBut they don\'t know that their session key has been exposed to M')
    print('s = ' + str(1))
    print(s_a == 1)

    #########################################################################
    print('\n\n*********  MITM IN ACTION _ g = p  *********')
    
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2

    print('\nAlice sends p,g to M...')
    print('p = ' + hex(p))
    print('g = ' + hex(g))

    print('M sends p and the malicious g = p to Bob...')
    g_b = p
    print('p = ' + hex(p))
    print('g = ' + hex(g_b))
    
    print('\nBob sends back ACK to M, then M forwards that to Alice...')
          
    ###  Alice  >>>
    a = random.randint(0, p-1)
    A = modexp(g, a, p)
    print('\nAlice sends M A = ' + hex(A))

    print('M sends A = p to Bob...')
    A_b = p

    ###  Bob  >>>
    b = random.randint(0, p-1)
    B = modexp(g_b, b, p)
    print('\nBob sends M B = ' + hex(B))
    print('M forwards that to Alice...')

    ###  Exchange their public keys (A and B) and calculate their session key  >>>
    # Alice sends confirmation message to make sure that they came up with the same session key
    msg = b'some dummy test message'
    s_a = modexp(B, a, p)
    key_a = hashlib.sha1( int2str(s_a) ).digest()[:16]
    w_a = KeyExpansion( key_a )
    iv = ''.join([chr(random.getrandbits(8)) for _ in range(16)])
    send_ab = str2bytes( Ciphers(pad(msg, 16), w_a, iv) )
    print('\nAlice sends Bob confirmation message: ' + str(send_ab))
    print('and the random iv used: ' + str(str2bytes(iv)))

    # Bob decodes that and encodes again the message with his session key and iv
    s_b = modexp(A_b, b, p)
    key_b = hashlib.sha1( int2str(s_b) ).digest()[:16]
    w_b = KeyExpansion( key_b )
    msg_rcv = depad(str2bytes(InvCiphers( send_ab, w_b, iv )), 16)
    iv = ''.join([chr(random.getrandbits(8)) for _ in range(16)])
    send_ba = str2bytes( Ciphers( pad(msg_rcv, 16), w_b, iv ) )
    print('\nBob sends back his comfirmation message: ' + str(send_ba))
    print('with the random iv used: ' + str(str2bytes(iv)))

    # Alice decodes and make sure that Bob has the same session key as her
    send_ba_decoded = depad( str2bytes(InvCiphers( send_ba, w_a, iv )), 16 )
    if send_ba_decoded == msg:
        print('\nOkay, Bob. I know you\'re there!')
    else:
        print('\nOh oh. Is that you, Bob? Or you\'re the hacker??')
        sys.exit()

    print('\nBut they don\'t know that their session key has been exposed to M')
    print('s = ' + str(0))
    print(s_a == 0)

    #########################################################################
    print('\n\n*********  MITM IN ACTION - g = p - 1  *********')
    
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2

    print('\nAlice sends p,g to M...')
    print('p = ' + hex(p))
    print('g = ' + hex(g))

    print('M sends p and the malicious g = p - 1 to Bob...')
    g_b = p - 1
    print('p = ' + hex(p))
    print('g = ' + hex(g_b))
    
    print('\nBob sends back ACK to M, then M forwards that to Alice...')
          
    ###  Alice  >>>
    a = random.randint(0, p-1)
    A = modexp(g, a, p)
    print('\nAlice sends M A = ' + hex(A))

    print('M sends A = p - 1 to Bob...')
    A_b = p - 1

    ###  Bob  >>>
    b = random.randint(0, p-1)
    B = modexp(g_b, b, p)
    s_bm = B
    print('\nBob sends M B = ' + hex(B))
    print('M forwards that to Alice')

    ###  Exchange their public keys (A and B) and calculate their session key  >>>
    # Alice sends confirmation message to make sure that they came up with the same session key
    msg = b'some dummy test message'
    s_a = modexp(B, a, p) # (-1) ** (a*b)
    key_a = hashlib.sha1( int2str(s_a) ).digest()[:16]
    w_a = KeyExpansion( key_a )
    iv = ''.join([chr(random.getrandbits(8)) for _ in range(16)])
    send_ab = str2bytes( Ciphers(pad(msg, 16), w_a, iv) )
    print('\nAlice sends M confirmation message: ' + str(send_ab))
    print('and the random iv used: ' + str(str2bytes(iv)))

    # M decrypt the message using s_am = 1 or -1
    s_am1 = 1
    key_am1 = hashlib.sha1( int2str(s_am1) ).digest()[:16]
    w_am1 = KeyExpansion( key_am1 )
    msg_am1 = depad(str2bytes(InvCiphers( send_ab, w_am1, iv )), 16)

    s_am2 = p - 1
    key_am2 = hashlib.sha1( int2str(s_am2) ).digest()[:16]
    w_am2 = KeyExpansion( key_am2 )
    msg_am2 = depad(str2bytes(InvCiphers( send_ab, w_am2, iv )), 16)
    
    if English_score( bytes2str(msg_am1) ) > English_score( bytes2str(msg_am2) ):
        s_am = s_am1
        key_am = key_am1
        w_am = w_am1
        msg_am = msg_am1
    else:
        s_am = s_am2
        key_am = key_am2
        w_am = w_am2
        msg_am = msg_am2

    # M then calculate the suitable key for B
    key_bm = hashlib.sha1( int2str(s_bm) ).digest()[:16]
    w_bm = KeyExpansion( key_bm )
    send_ab = str2bytes( Ciphers(pad(msg_am, 16), w_bm, iv) )
    print('M sends Bob the forged confirmation message: ' + str(send_ab))
    print('and the random iv used: ' + str(str2bytes(iv)))

    # Bob decodes that and encodes again the message with his session key and iv
    s_b = modexp(A_b, b, p)
    key_b = hashlib.sha1( int2str(s_b) ).digest()[:16]
    w_b = KeyExpansion( key_b )
    msg_rcv = depad(str2bytes(InvCiphers( send_ab, w_b, iv )), 16)
    iv = ''.join([chr(random.getrandbits(8)) for _ in range(16)])
    send_ba = str2bytes( Ciphers( pad(msg_rcv, 16), w_b, iv ) )
    print('\nBob sends back his comfirmation message to M: ' + str(send_ba))
    print('with the random iv used: ' + str(str2bytes(iv)))

    # M changes the message from using k_b to using k_a
    msg_bm = depad(str2bytes(InvCiphers( send_ba, w_bm, iv )), 16)
    send_ba = str2bytes( Ciphers( pad(msg_bm, 16), w_am, iv ) )
    print('M sends forged Bob\'s comfirmation message to Alice: ' + str(send_ba))
    print('with the random iv used: ' + str(str2bytes(iv)))

    # Alice decodes and make sure that Bob has the same session key as her
    send_ba_decoded = depad( str2bytes(InvCiphers( send_ba, w_a, iv )), 16 )
    if send_ba_decoded == msg:
        print('\nAlice: Okay, Bob. I know you\'re there!')
    else:
        print('\nAlice: Oh oh. Is that you, Bob? Or you\'re the hacker??')
        sys.exit()

    print('\nBut they don\'t know that their session key has been exposed to M')
    print('s_a = ' + str(s_am))
    print('s_b = ' + str(s_bm))
    print(s_a == s_am and s_b == s_bm)

    time_elapsed = time.time() - start_time
    print('\nTime elapsed: ' + str(time_elapsed))

if __name__ == '__main__':
    main()
