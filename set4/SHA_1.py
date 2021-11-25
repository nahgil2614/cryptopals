#const
mask = 0xffffffff
#bitwise operations have the least priority

#Note 1: all variables are unsigned 32-bit quantities and wrap modulo 2**32 when calculating, except for
    #ml, message length: 64-bit quantity, and
    #hh, message digest: 160-bit quantity
#Note 2: big endian

key = b'TEST_KEY'

def getMessage():
    f = open('28.txt', 'r')
    mes = b''
    for line in f:
        mes += bytes([ord(ltr) for ltr in line])
    return mes

mes = getMessage()

def big_endian_64_bit( num ):
    num = hex(num).replace('0x','').rjust(16,'0')
    return bytes([int(num[i:i+2], 16) for i in range(0, len(num), 2)])

def leftrot( num ):
    return ((num << 1) & mask) + (num >> 31)

def bytes2int( block ):
    return sum([block[len(block)-1-i] * (256**i) for i in range(len(block))])

def leftrotate(num, offset):
    num_type = type(num)
    if num_type == bytes:
        num = bytes2int(num)
    for i in range(offset):
        num = leftrot(num)
    if num_type == bytes:
        num = big_endian_64_bit( num )[4:]
    return num

def XOR( block1, block2, block3, block4 ):
    return bytes([x^y^z^t for x,y,z,t in zip(block1, block2, block3, block4)])

def SHA1( message ):
        
    #Initialize variable:

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    ml = len(message) * 8

    #Pre-processing
    message += b'\x80'
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'
    message += big_endian_64_bit( ml % (2**64))

    #Process the message in successive 512-bit chunks:
    chunks = [message[i:i+64] for i in range(0, len(message), 64)]
    for chunk in chunks:
        w = [chunk[i:i+4] for i in range(0, 64, 4)]

        #Message schedule: extend the sixteen 32-bit words into eighty 32-bit words:
        for i in range(16, 80):
            #Note 3: SHA-0 differs by not having this leftrotate.
            w += [leftrotate( XOR(w[i-3], w[i-8], w[i-14], w[i-16]), 1 )]

        #Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        #Main loop:
        for i in range(80):
            f = 0
            k = 0
            if i in range(20):
                f = (b & c) | ((b ^ mask) & d)
                k = 0x5A827999
            elif i in range(20,40):
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i in range(40,60):
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            elif i in range(60,80):
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (leftrotate(a, 5) + f + e + k + bytes2int(w[i])) % (2**32)
            e = d
            d = c
            c = leftrotate(b, 30)
            b = a
            a = temp

        #Add this chunk's hash to result so far:
        h0 = (h0 + a) % (2**32)
        h1 = (h1 + b) % (2**32) 
        h2 = (h2 + c) % (2**32)
        h3 = (h3 + d) % (2**32)
        h4 = (h4 + e) % (2**32)

    #Produce the final hash value (big-endian) as a 160-bit number:
    hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    return hh

def main():
    print(hex(SHA1( key + mes )).replace('0x','').rjust(40,'0'))
    print(hex(SHA1( b'' )).replace('0x','').rjust(40,'0'))

if __name__ == '__main__':
    main()
