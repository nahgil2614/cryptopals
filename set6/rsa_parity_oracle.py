from decimal import *

import base64
import time

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

def parity_oracle( c ):
    return not (modexp(c, d, n) & 1)

def main():
    global n
    global d
    
    start_time = time.time()

    #generate 2 random primes
    p = 0xe18fa5cceb7d01853709f4f06b14e4e326ddf017398e86e960e9f64c5dc9e979f886ce0f1f6f186abf8fd6528feacabd99e6316878703372bb700dd83d5b53c9
    q = 0x9c48755b67cb3d57ca5a72520f901e479ef3bf8839ae9689e62cbeaa3b3685224b8a381c41dcae1338752c67522ced84dd5a0cb90359b1a8b0ec5424cabe738b

    n = p * q #1024-bit modulus
    et = (p - 1) * (q - 1)
    e = 65537 #encryption key

    d = invmod(e, et) #decryption key

    #public key is [e,n] | private key is [d,n]
    getcontext().prec = 10000 #set precision

    msg = b'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='
    m = bytes2int( base64.b64decode( msg ) )
    c = modexp(m, e, n) #will be modified (* (2 ** k) ** e) to produce m'

    #attacker can call parity_oracle, n, e
    #n = p * q: 2 large prime => n is odd
    frac_up_bound = Decimal(str(n)) - Decimal('1')
    frac_low_bound = Decimal('0')
    upper_bound = frac_up_bound.quantize(Decimal('1.'), rounding=ROUND_DOWN)
    lower_bound = frac_low_bound.quantize(Decimal('1.'), rounding=ROUND_UP)

    while upper_bound != lower_bound:
        c = (c * modexp(2, e, n)) % n
        if parity_oracle( c ):
            frac_up_bound = (frac_low_bound + frac_up_bound) / Decimal('2')
            upper_bound = frac_up_bound.quantize(Decimal('1.'), rounding=ROUND_DOWN)
        else:
            frac_low_bound = (frac_low_bound + frac_up_bound) / Decimal('2')
            lower_bound = frac_low_bound.quantize(Decimal('1.'), rounding=ROUND_UP)

    recovered_m = int(lower_bound)
    recovered_msg = int2bytes( recovered_m )
    print('Message has been recovered using parity_oracle:\n' + str(recovered_msg))
    
    time_elapsed = time.time() - start_time
    print('\nTime elapsed: ' + str(time_elapsed))

if __name__ == '__main__':
    main()
