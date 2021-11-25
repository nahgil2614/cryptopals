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

def main():
    start_time = time.time()

    #generate 2 random primes
    p = 0x9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA9614B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F84380B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0BE3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF56EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734AF7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB
    q = 0xEEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3

    n = p * q
    print(n)
    et = (p - 1) * (q - 1)
    e = 3 #encryption key

    d = invmod(e, et) #decryption key

    #public key is [e,n] | private key is [d,n]

    m = b'Hello from the other sideeeeeeeeeeeeeeee. This test message is pretty long, I promise :v the longest? Not that much, but I will try to make it as long as possible :)) hahahaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa. How about some random nonsense tailing the make it even longer :V' # I tried to make RSA uncapable of holding this message\'s decrypted version LOL :v how dumb am I?' #message
    print('\nMessage = ' + str(m))
    
    #encrypting...
    c = modexp(bytes2int(m), e, n) #cipher
    print('\nCipher = ' + str(c))

    #decrypting...
    m = int2bytes(modexp(c, d, n))
    print('\nMessage = ' + str(m))

    time_elapsed = time.time() - start_time
    print('\nTime elapsed: ' + str(time_elapsed))

if __name__ == '__main__':
    main()
