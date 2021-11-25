import hashlib
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

def int2bytes( num ):
    mask = 0b11111111
    res = []
    while num != 0:
        res += [num & mask]
        num >>= 8
    return bytes(res[::-1])

def para_gen():
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
    return p,q,g

def per_user_keys(p,q,g):
    x = random.randint(1, q-1) #private key    
    y = modexp(g, x, p) #public key
    return x,y

def sign( m, p, q, g, x ):

    r,s = 0,0
    while r == 0 or s == 0:
        k = random.randint(0, 2**16)
        try:
            invmod(k, q)
        except:
            pass
        else:
            r = modexp(g, k, p) % q
            s = (invmod(k, q) * ( (m + x*r) % q )) % q
    return r,s

def isValid( m, r, s, p, q, g, y ):
    if r <= 0 or r >= q or s <= 0 or s >= q:
        return False
    w = invmod(s, q)
    u1 = (m * w) % q
    u2 = (r * w) % q
    v = (((modexp(g, u1, p) % p) * (modexp(y, u2, p) % p)) % p) % q
    if v != r:
        return False
    return True    

def infected_sign( m, p, q, g, x, k ):
    r,s = 0,0
    while r == 0 or s == 0:
        try:
            invmod(k, q)
        except:
            return 0,0
        else:
            r = modexp(g, k, p) % q
            s = (invmod(k, q) * ( (m + x*r) % q )) % q
    return r,s

def str2bytes( string ):
    return bytes([ord(ltr) for ltr in string])

def main():
    start_time = time.time()

    print('=============  DEMO ==============')
    msg = b'Hello the stupid world!'
    m = bytes2int(hashlib.sha1( msg ).digest())

    print('msg: ' + str(msg))
    print('m:   ' + str(m))
    
    p,q,g = para_gen()
    x,y = per_user_keys(p, q, g)
    print('x  = ' + str(x))

    #signature
    r,s = sign(m, p, q, g, x)
    
    print('\nsignature:')
    print('r  = ' + str(r))
    print('s  = ' + str(s))

    print('verifier say: ' + str(isValid(m, r, s, p, q, g, y)))

    print('\n==================  g = 0  =====================')
    time.sleep(2)
    print('Get in infinite loop due to r = 0 always...')

    print('\n==================  g = p + 1  =====================')
    print('Now y = r = v = 1 always => no need to calculate r,s ;\nThe attacker now can forged any message\'s signature using r = 1')

    msgs = [b'Hello, world', b'Goodbye, world', b'Hahaha', b'Play with me~', b'Comm\'onnnn']
    for msg in msgs:
        m = bytes2int(hashlib.sha1( msg ).digest())
        print('\nmsg: ' + str(msg))
        print('m:   ' + str(m))
        
        p,q,g = para_gen()
        g = p + 1
        x,y = per_user_keys(p, q, g)
        print('the user has x = ' + str(x))
        print('but the attacker only need to inject r = 1 :D')
        print('\ninjecting r = s = 1 to verify...')
        r = 1
        s = 1
        time.sleep(1)
        print('verifier say: ' + str(isValid(m, r, s, p, q, g, y)))
    
    time_elapsed = time.time() - start_time
    print('\nTime elapsed: ' + str(time_elapsed))

if __name__ == '__main__':
    main()
