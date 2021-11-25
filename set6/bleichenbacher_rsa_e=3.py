import sys
import hashlib
import time
from decimal import *

#NOTE : this attack only use SHA-1 as a reference, attack for other has can be derived

#const
asn1_sha1 = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'

#some parser requires the \xff part to be at least 8-byte long
prefix = b'\x00\x01\xff\xff\xff\xff\xff'#\xff\xff\xff' #the stricter the verifier,
                                                       #the harder to get through
#for larger modulus n, it's harder to factorize, but if e is small (e.g. e=3), then larger n
#would be a huge advantage for the attacker, become they have more room for adjustment of the garbage

def modexp(A, b, c): #return A**b mod c
    x = A
    R = 1
    while b != 0:
        if b & 1:
            R = (R * x) % c
        b >>= 1
        x = (x * x) % c
    return R

def egcd( a, b ): #return gcd(a,b) and Bezout's coefficients for (a,b)
    r0, r1 = a, b
    s0, s1 = 1, 0
    t0, t1 = 0, 1
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        s0, s1 = s1, s0 - q * s1
        t0, t1 = t1, t0 - q * t1
    return r0, s0, t0

def invmod(a, m): #find a^(-1) mod m
    gcd, x, y = egcd(a,m)
    if gcd != 1:
        raise Exception('Modular inverse does not exist!')
    else:
        return x % m

# judge the string as a big-endian representation of a number
def bytes2int( string ):
    return sum([string[i] * (256**( len(string) - 1 - i )) for i in range(len(string))])

def int2bytes( num ):
    mask = 0b11111111
    res = []
    while num != 0:
        res += [num & mask]
        num >>= 8
    return bytes(res[::-1])

def byte_length( num ):
    res = 0
    while num != 0:
        res += 1
        num >>= 8
    return res

def sign( mes, d, n ):
    hash_ = hashlib.sha1( mes ).digest()

    key_length = byte_length( n ) 
    #pad the hash
    padded_hash = prefix + b'\xff'*(key_length - len(prefix + b'\x00' + asn1_sha1 + hash_)) + b'\x00' + asn1_sha1 + hash_   
    #encrypt with private key
    return modexp( bytes2int(padded_hash), d, n )

def verify( mes, signature, e, n ):
    padded_hash = int2bytes(modexp( signature, e, n )).rjust(byte_length( n ), b'\x00')

    if padded_hash[:len(prefix)] != prefix:
        raise Exception('BadSignature: Verification failed.')

    sep_index = padded_hash.find(b'\x00',1)
    if sep_index == -1:
        raise Exception('BadSignature: Verification failed.')
    if padded_hash[len(prefix) : sep_index].count(b'\xff') != sep_index - len(prefix):
        raise Exception('BadSignature: Verification failed.')

    #check if SHA_1
    if not padded_hash[sep_index + 1 : ].startswith( asn1_sha1 ):
        raise Exception('BadSignature: Verification failed.')
    hash_ = padded_hash[sep_index + 1 + len(asn1_sha1) : sep_index + 1 + len(asn1_sha1) + 20]

    return hashlib.sha1( mes ).digest() == hash_

def main():
    start_time = time.time()

    #generate 2 random primes
    p = 0xe18fa5cceb7d01853709f4f06b14e4e326ddf017398e86e960e9f64c5dc9e979f886ce0f1f6f186abf8fd6528feacabd99e6316878703372bb700dd83d5b53c9
    q = 0x9c48755b67cb3d57ca5a72520f901e479ef3bf8839ae9689e62cbeaa3b3685224b8a381c41dcae1338752c67522ced84dd5a0cb90359b1a8b0ec5424cabe738b

    n = p * q #1024-bit key
    e = 3
    et = (p - 1) * (q - 1)

    d = invmod(e, et)

    print('Normal user')
    messages = [b'hi mom']
    for message in messages:
        signature = sign( message, d, n )
        print(verify(message, signature, e, n))

    print('\nAttacker attacking e = 3 scheme only')
    key_length = byte_length(n)
    print('Key length = ' + str(key_length))
    message = b'hi mom'
    forged_padded_hash = prefix + b'\x00' + asn1_sha1 + hashlib.sha1( message ).digest()

    trailing_zeros = key_length - len(forged_padded_hash)
    forged_padded_hash += b'\x00' * trailing_zeros

    print('\nforged_padded_hash = ' + str(forged_padded_hash))
    
    getcontext().prec = 1000

    forged_signature = (Decimal( bytes2int(forged_padded_hash) ) ** ( Decimal(1) / Decimal(3) )).quantize( Decimal(1.), rounding=ROUND_UP )

    if (forged_signature ** Decimal(3)) - Decimal( bytes2int(forged_padded_hash) ) < Decimal(2) ** Decimal(trailing_zeros*8):
        print('\nBleichenbacher\'s attack is possible!')
    else:
        print('\nMission impossible :(')
        sys.exit()
    
    if verify(message, int(forged_signature), e, n):
        print('\nYayyyyy we have did it!!!!')
        print('message = ' + str(message))
        print('real signature = ' + str(sign( message, d, n )))
        print('forged signature = ' + str(forged_signature))
    else:
        print('\nSomething has gone wrong...')
    
    time_elapsed = time.time() - start_time
    print('\nTime elapsed: ' + str(time_elapsed))

if __name__ == '__main__':
    main()
