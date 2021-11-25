# for calculating root, don't use a ** 1/b.
# use 10 ** (log(a, 10) / b) instead (python log function can take in an insanely huge input! Believe me

import time
from math import log
from decimal import *

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

# judge the string as a little-endian representation of a number
def bytes2int( string ):
    return sum([string[i] * (256**i) for i in range(len(string))])

def int2bytes( num ):
    mask = 0b11111111
    res = []
    while num != 0:
        res += [num & mask]
        num >>= 8
    return bytes(res)        

p = [64135289477071580278790190170577389084825014742943447208116859632024532344630238623598752668347708737661925585694639798853367,
     509435952285839914555051023580843714132648382024111473186660296521821206469746700620316443478873837606252372049619334517,
     33478071698956898786044169848212690817704794983713768568912431388982883793878002287614711652531743087737814467999489]

q = [244624208838318150567813139024002896653802092578931401452041221336558477095178155258218897735030590669041302045908071447,
     33372027594978156556226010605355114227940760344767554666784520987023841729210037080257448673296881877565718986258036932062711,
     36746043666799590428244633799627952632279158164343087642676032283815739666511279233373417143396810270092798736308917]

def main():
    start_time = time.time()

    n = []
    e = 3 #encryption key
    m = b'Hello from the other sideeeeeeeeeeeeee. OMG really long message' #message
    c = []
    
    for i in range(3):
        #generate 2 random primes p[i], q[i]

        n += [p[i] * q[i]]

        #using public key [e,n] to encrypt 1 message 3 times with different keys
        
        #encrypting...
        c += [modexp(bytes2int(m), e, n[i])] #cipher
        
        print('\nCipher = ' + str(c[i]))

    #decrypting using Chinese Remainder Theorem...
    N = n[0] * n[1] * n[2]
    x = ( c[0]*n[1]*n[2]*invmod(n[1]*n[2], n[0]) + c[1]*n[0]*n[2]*invmod(n[0]*n[2], n[1]) + c[2]*n[0]*n[1]*invmod(n[0]*n[1], n[2]) ) % N

    #have to do this ridiculous thing to improve accuracy for longer message
    getcontext().prec = len(str(x))
    x = int((Decimal(x) ** (Decimal(1)/Decimal(e))).quantize(Decimal('1.'), rounding=ROUND_UP))
    
    print('\n')
    print(int2bytes(x))

    time_elapsed = time.time() - start_time
    print('\nTime elapsed: ' + str(time_elapsed))

if __name__ == '__main__':
    main()
