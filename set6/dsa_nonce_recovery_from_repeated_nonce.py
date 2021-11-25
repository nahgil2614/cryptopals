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

def str2bytes( string ):
    return bytes([ord(ltr) for ltr in string])

def getData():
    msg, s, r, m = [], [], [], []
    f = open('44.txt', 'r')
    for line in f:
        if line.startswith('msg: '):
            msg += [str2bytes(line.replace('msg: ','').replace('\n',''))]
        elif line.startswith('s: '):
            s += [int(line.replace('s: ','').replace('\n',''))]
        elif line.startswith('r: '):
            r += [int(line.replace('r: ','').replace('\n',''))]
        elif line.startswith('m: '):
            m += [int(line.replace('m: ','').replace('\n',''), 16)]
    return msg, s, r, m

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
    msg, s, r, m = getData()

    p,q,g = para_gen()
    #the user public key
    y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821

    #public knowledge is: msg, m, p, q, g, y, r, s
    #private knowlegde: x
    #random nonce: k

    #check if there are repeated k, then exploit from that
    length = len(msg) #number of signatures

    out = False
    for i in range(length - 1):
        for j in range(i + 1, length):
            try:
                invmod( s[i] - s[j], q )
            except:
                pass
            else:
                k = (invmod( s[i] - s[j], q ) * ( m[i] - m[j] ) % q) % q
                x = (invmod(r[i], q) * (((s[i] * k) - m[i]) % q)) % q
                if infected_sign( m[i], p, q, g, x, k ) == (r[i], s[i]): #tuple cmp
                    print('x found at:')
                    print('i = ' + str(i))
                    print('j = ' + str(j))
                    out = True
                    break
        if out:
            break                
    
    print('user has used x = ' + str(x))
    print(hashlib.sha1( str2bytes(hex(x).replace('0x','')) ).hexdigest() == 'ca8f6f7c66fa362d40760d135b763eb8527d3d52')
    
    time_elapsed = time.time() - start_time
    print('\nTime elapsed: ' + str(time_elapsed))

if __name__ == '__main__':
    main()
