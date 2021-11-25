#const
mask = 0xffffffff
#bitwise operations have the least priority

#Note 1: all variables are unsigned 32-bit quantities and wrap modulo 2**32 when calculating, except for
    #ml, message length: 64-bit quantity, and
    #hh, message digest: hex string in little-endian
    #little-endian for bytes ordering and big-endian for bits-in-byte

key = b'TEST_KEY'

def getMessage():
    f = open('28.txt', 'r')
    mes = b''
    for line in f:
        mes += bytes([ord(ltr) for ltr in line])
    return mes

mes = getMessage()

def little_endian_64_bit( num ):
    res = hex(num).replace('0x','').rjust(16,'0')
    return bytes([int(res[i:i+2], 16) for i in range(14,-1,-2)])

def leftrot( num ):
    return ((num << 1) & mask) + (num >> 31)

def bytes2int( block ):
    return sum([block[i] * (256**i) for i in range(len(block))])

def leftrotate(num, offset):
    num_type = type(num)
    if num_type == bytes:
        num = bytes2int(num)
    for i in range(offset):
        num = leftrot(num)
    if num_type == bytes:
        num = little_endian_64_bit( num )[:4]
    return num

def f( x, y, z ):
    return (x & y) | ((x ^ mask) & z)

def g( x, y, z ):
    return (x & y) | (x & z) | (y & z)

def h( x, y, z ):
    return x ^ y ^ z

def MD4( message ):
        
    #Initialize variable:

    A = 0x67452301
    B = 0xefcdab89
    C = 0x98badcfe
    D = 0x10325476

    b = len(message) * 8

    #Pre-processing
    message += b'\x80'
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'
    message += little_endian_64_bit( b % (2**64) )

    N = len(message) // 4
    
    #Process the message in successive 32-bit words:
    M = [bytes2int(message[i:i+4]) for i in range(0, len(message), 4)]
    for i in range(N//16): #process each 16-word block
        X = [M[i*16+j] for j in range(16)]
        AA = A
        BB = B
        CC = C
        DD = D

        buff = [A, B, C, D]
        #Round 1
        last = [3,7,11,19]
        for t in range(16):
            buff[(4-t%4)%4] = leftrotate((buff[(4-t%4)%4] + f(buff[(4-t%4+1)%4], buff[(4-t%4+2)%4], buff[(4-t%4+3)%4]) + X[t]) % (2**32), last[t%4])

        #Round 2
        last = [3,5,9,13]
        mid = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]
        for t in range(16):
            buff[(4-t%4)%4] = leftrotate((buff[(4-t%4)%4] + g(buff[(4-t%4+1)%4], buff[(4-t%4+2)%4], buff[(4-t%4+3)%4]) + X[mid[t]] + 0x5a827999) % (2**32), last[t%4])

        #Round 3
        last = [3,9,11,15]
        mid = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]
        for t in range(16):
            buff[(4-t%4)%4] = leftrotate((buff[(4-t%4)%4] + h(buff[(4-t%4+1)%4], buff[(4-t%4+2)%4], buff[(4-t%4+3)%4]) + X[mid[t]] + 0x6ed9eba1) % (2**32), last[t%4])

        A,B,C,D = buff
        
        A = (A + AA) % (2**32)
        B = (B + BB) % (2**32)
        C = (C + CC) % (2**32)
        D = (D + DD) % (2**32)

    hh = little_endian_64_bit(A)[:4] + little_endian_64_bit(B)[:4] + little_endian_64_bit(C)[:4] + little_endian_64_bit(D)[:4]
    return ''.join([hex(byte).replace('0x','').rjust(2,'0') for byte in hh])

def main():
    print(MD4(b''))
    print(MD4(b'a'))
    print(MD4(b'abc'))
    print(MD4(b'message digest'))
    print(MD4(b'abcdefghijklmnopqrstuvwxyz'))

if __name__ == '__main__':
    main()
