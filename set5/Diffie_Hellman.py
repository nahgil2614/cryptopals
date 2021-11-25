import time
import sys
import random

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
    start_time = time.time()
    
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2

    ###  Alice  >>>
    a = random.randint(0, p-1)
    A = modexp(g, a, p)
    print('A = ' + hex(A))

    ###  Bob  >>>
    b = random.randint(0, p-1)
    B = modexp(g, b, p)
    print('B = ' + hex(B))

    ###  Exchange their public keys (A and B) and calculate their session key  >>>
    s = modexp(B, a, p)
    if s != modexp(A, b, p):
        print('Session keys don\'t match!')
        sys.exit()

    print('Private key: ' + hex(s))

    time_elapsed = time.time() - start_time
    print('Time elapsed: ' + str(time_elapsed))

if __name__ == '__main__':
    main()
