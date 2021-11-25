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

def main():
    # Client and Server both agree on these parameters - câu chuyện của quá khứ
    N = 0xEEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3
    g = 2
    k = 3
    I = b'nahgil2614' #email
    P = b'omg_im superman lol good old time with KC2' #password

    # Server
    salt = random.randint(0, N-1)
    xH = hashlib.sha256( str2bytes(str(salt)) + P )
    x = int( xH.hexdigest(), 16 )
    v = modexp(g, x, N)
    x, xH = 0, 0 #save every thing but x, xH

    # Nếu muốn bypass thì bắt đầu giả danh Client từ đây
    # giờ thì attacker không có password nên chỗ nào của Client có P thì phải xử lý hết
    # Client sends request: I, A
    a = random.randint(0, N-1)
    # A có thể = N * t (t là số tự nhiên)
    A = N * random.randint(0, N-1) #modexp(g, a, N)

    # Server sends salt, B
    b = random.randint(0, N-1)
    B = k*v + modexp(g, b, N)

    # S,C compute
    uH = hashlib.sha256( str2bytes(str(A) + str(B)) )
    u = int(uH.hexdigest(), 16)

    # Client
    #xH = hashlib.sha256( str2bytes(str(salt)) + P )
    #x = int( xH.hexdigest(), 16 )
    S_c = 0 #modexp( (B - k * modexp(g, x, N)) % N, a + u * x, N )
    K_c = hashlib.sha256( str2bytes(str(S_c)) ).digest()

    print(S_c)

    # Server
    S_s = modexp( (A * modexp(v, u, N)) % N, b, N )
    K_s = hashlib.sha256( str2bytes(str(S_s)) ).digest()

    print('\n' + str(S_s))

    # Client send confirmation message
    mes = HMAC_SHA256( K_c, str2bytes(str(salt)) )

    # Server check
    if mes == HMAC_SHA256( K_s, str2bytes(str(salt)) ):
        print('OK')
    else:
        print('No OK.')
    

if __name__ == '__main__':
    main()
