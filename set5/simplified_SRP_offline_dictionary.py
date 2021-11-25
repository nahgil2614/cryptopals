import time
import random
import hashlib

def XOR( block1, block2 ):
    return bytes([x^y for x,y in zip(block1, block2)])

def HMAC_SHA256( K, m ):
    if len(K) > 64:
        K = hashlib.sha256( K ).digest() + bytes(32)
    else:
        while len(K) < 64:
            K += b'\x00'
    o_key_pad = XOR( b'\x5c' * 64, K )
    i_key_pad = XOR( b'\x36' * 64, K )
    return hashlib.sha256(o_key_pad + hashlib.sha256(i_key_pad + m).digest()).digest()

def str2bytes( string ):
    return bytes([ord(ltr) for ltr in string])

def modexp(A, b, c): #return A**b mod c
    x = A
    R = 1
    while b != 0:
        if b & 1:
            R = (R * x) % c
        b >>= 1
        x = (x * x) % c
    return R

def getPasswords():
    f = open('38.txt')
    res = []
    for line in f:
        res += [str2bytes(line.replace('\n',''))]
    return res

def main():
    start_time = time.time()
    
    # attack kì này thì attacker là MITM, giả làm server chứ không giả làm client như lần zero key nữa
    # giờ phải làm sao đó để crack được password
    # password database này gồm 10**6 password :v hugeeeee
    
    # Client and Server both agree on these parameters
    N = 0xEEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3
    g = 2
    I = b'nahgil2614' #email
    passwords = getPasswords()
    P = passwords[random.randint(0, len(passwords) - 1)] #password

    # MY ATTACK WOULD BE SET b = 1 => B = g & u = 1 & salt = 0
    # thiệt ra thì cho b,B,u,salt là arbitrary cũng được, không thành vấn đề quá lớn
    
    # Server
    salt = 0
    #x = int( hashlib.sha256( str2bytes(str(salt)) + P ).hexdigest(), 16 )
    #v = modexp(g, x, N)
    #x = 0 #save every thing but x

    # Client sends request: I, A
    a = random.randint(0, N-1)
    A = modexp(g, a, N)

    # Server sends salt, B, u
    b = 1
    B = modexp(g, b, N)
    u = 1

    # Client
    x = int( hashlib.sha256( str2bytes(str(salt)) + P ).hexdigest(), 16 )
    S_c = modexp( B, a + u * x, N )
    K_c = hashlib.sha256( str2bytes(str(S_c)) ).digest()

    # Server
    #S_s = modexp( (A * modexp(v, u, N)) % N, b, N )
    #K_s = hashlib.sha256( str2bytes(str(S_s)) ).digest()
    
    # Client send confirmation message
    mes = HMAC_SHA256( K_c, str2bytes(str(salt)) )

    ###########  The attack starts  ############
    # Server (attacker) then use that HMAC to crack the password check

    check = b''
    for password in passwords:
        x = int( hashlib.sha256( b'0' + password ).hexdigest(), 16 )
        v = modexp(g, x, N)
        S_s = modexp( (A * (v % N)) % N, b, N )
        K_s = hashlib.sha256( str2bytes(str(S_s)) ).digest()
        check = HMAC_SHA256( K_s, str2bytes(str(salt)) )
        if check == mes:
            break
    print('The attacker found: ' + str(password))
    print('Real client\'s password: ' + str(P))

    time_elapsed = time.time() - start_time
    print('Time elapsed: ' + str(time_elapsed))

if __name__ == '__main__':
    main()
