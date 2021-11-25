from decimal import *

import portion as P
import random
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

def int2bytes_( num ):
    mask = 0b11111111
    res = []
    while num != 0:
        res += [num & mask]
        num >>= 8
    return bytes(res[::-1]).rjust( byte_length( n ), b'\x00' ) #message is PKCS-padded

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

def pad( mes ): #PKCS1 v1.5 ; mes: bytes ; n: modulus
    return b'\x00\x02' + bytes([random.randint(1,255) for _ in range(byte_length( n ) - len(mes) - 3)]) + b'\x00' + mes

def oracle( c ): #telling if m of this cipher is PKCS conforming or not
    return int2bytes_( modexp(c, d, n) )[:2] == b'\x00\x02'

def main():
    global n
    global d
    
    start_time = time.time()

    #generate 2 random primes
    p = 0xe202affce890fb313b41fabb92023f1f3e7eb038df8d9bb84c07de0f315cb7b7
    q = 0xd5f866263835ac7a56bf97f8309a7e3007241ed13131c7dbcb29fd6abc24fbf70056653df3405cb3d449f0f966b91f710049593afbc1e13a7ecaf71ef276e557

    n = p * q #768-bit modulus
    et = (p - 1) * (q - 1)
    e = 65537 #encryption key

    d = invmod(e, et) #decryption key

    #public key is [e,n] | private key is [d,n]
    msg = pad(b'Hello everyone.')
    m = bytes2int(msg)
    c = modexp(m, e, n)

    #Now, the attacker only have c, e, n, and the oracle in hand...
    #His ultimate goal is to retrieve m = modexp(c, d, n) without knowing d...

    B = 1 << (byte_length(n) * 8 - 16)
    
    #Step 1: Blinding
    s0 = 1
    c0 = c
    M = P.closed(2*B, 3*B-1)
    i = 1
    
    getcontext().prec = 1000

    while 1:
        print(M)
        #Step 2: Searching for PKCS conforming messages
        if i == 1:
            s = int((Decimal(n) / Decimal(3 * B)).quantize(Decimal('1.'), rounding=ROUND_UP))
            while not oracle( (c * modexp(s, e, n)) % n ):
                s += 1
        elif M.enclosure != M: #at least 2 intervals in M
            s += 1
            while not oracle( (c * modexp(s, e, n)) % n ):
                s += 1
        else:
            ri = int((Decimal(2 * (M.upper * s - 2 * B)) / Decimal(n)).quantize(Decimal('1.'), rounding=ROUND_UP))
            s = 0 #đã chuyển thông tin vô ri
            while not oracle( (c * modexp(s, e, n)) % n ):
                low = int((Decimal(2*B + ri*n) / Decimal(M.upper)).quantize(Decimal('1.'), rounding=ROUND_UP))
                up = int((Decimal(3*B + ri*n) / Decimal(M.lower)).quantize(Decimal('1.'), rounding=ROUND_UP))
                for s in range(low, up):
                    if oracle( (c * modexp(s, e, n)) % n ):
                        break
                ri += 1
        
        #Step 3: Narrowing the set of solutions
        res = P.empty()
        for interval in M:
            low = int((Decimal(interval.lower*s - 3*B + 1) / Decimal(n)).quantize(Decimal('1.'), rounding=ROUND_UP))
            up = int((Decimal(interval.upper*s - 2*B) / Decimal(n)).quantize(Decimal('1.'), rounding=ROUND_DOWN))
            for r in range(low, up+1):
                left = int((Decimal(2*B + r*n) / Decimal(s)).quantize(Decimal('1.'), rounding=ROUND_UP))
                right = int((Decimal(3*B - 1 + r*n) / Decimal(s)).quantize(Decimal('1.'), rounding=ROUND_DOWN))
                res |= P.closed( max(interval.lower, left), min(interval.upper, right) )
        M = res

        #Step 4: Computing the solution
        if M.upper == M.lower:
            m_calc = (M.upper * invmod(s0, n)) % n
            break
        i += 1

    print('\nrestored message: ' + str(int2bytes_(m_calc)))
    print(m_calc == m)

    print('\n' + str(i) + ' s value have been calculated!')

    time_elapsed = time.time() - start_time
    print('\nTime elapsed: ' + str(time_elapsed))

if __name__ == '__main__':
    main()
