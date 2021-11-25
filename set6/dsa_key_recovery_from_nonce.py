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
    global nonce

    r,s = 0,0
    while r == 0 or s == 0:
        k = random.randint(0, 2**16)
        nonce = k
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

nonce = 0

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

def main():
    start_time = time.time()

    print('=============  DEMO ==============')
    msg = b'Hello the stupid world!'
    m = bytes2int(hashlib.sha1( msg ).digest())
    p,q,g = para_gen()
    x,y = per_user_keys(p, q, g)
    print('x  = ' + str(x))

    #signature
    r,s = sign(m, p, q, g, x)
    
    print('k = ' + str(nonce))
    x_calc = (invmod(r, q) * (((s * nonce) - m) % q)) % q
    print('x_ = ' + str(x_calc))
    print('key recover? ' + str(infected_sign( m, p, q, g, x_calc, nonce ) == (r, s)))

    #######################################################################
    print('\n=========  NOW LET\'S RECOVER THE KEY  =========')
    msg = b'For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n'
    m = bytes2int(hashlib.sha1( msg ).digest())
    p,q,g = para_gen()
    #the user public key
    y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940

    print('msg actually from user? ' + str(isValid(m, r, s, p, q, g, y)))

    #public knowledge is: msg, m, p, q, g, y, r, s
    #private knowlegde: x
    #random nonce: k
    
    for k in range(2**16 + 1):
        x = (invmod(r, q) * (((s * k) - m) % q)) % q
        if infected_sign( m, p, q, g, x, k ) == (r, s): #tuple cmp
            print('k found at k = ' + str(k))
            break

    print('user has used x = ' + str(x))
    
    time_elapsed = time.time() - start_time
    print('\nTime elapsed: ' + str(time_elapsed))

if __name__ == '__main__':
    main()
