###################################  SERVER'S SIDE  ###################################
#const
mask = 0xffffffff
#bitwise operations have the least priority

#Note 1: all variables are unsigned 32-bit quantities and wrap modulo 2**32 when calculating, except for
    #ml, message length: 64-bit quantity, and
    #hh, message digest: 160-bit quantity
#Note 2: big endian

key = b'SuPeR_sEcReT_kEy,_NoT_tO_bE_gUeSsEd_So_EaSiLy'

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

def SHA1( message ): #the inner mechanism only
        
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

def isValid( message, hh ):
    res = False
    if SHA1(key + message) == hh:
        res = True
    return res

###################################  ATTACKER'S SIDE  ###################################
def pad( bytelength ): #MD_padding
    ml = bytelength * 8

    #Pre-processing
    padding = b'\x80'
    while ((bytelength + len(padding)) * 8) % 512 != 448:
        padding += b'\x00'
    padding += big_endian_64_bit( ml )
    return padding

def SHA1_LE(old_hh, wanna_be, length):

    if (len(wanna_be + pad(length)) * 8) % 512 != 0:
        hh = -1
    else:
        #Initialize variable:

        h0 = (old_hh & (mask << 128)) >> 128
        h1 = (old_hh & (mask << 96)) >> 96
        h2 = (old_hh & (mask << 64)) >> 64
        h3 = (old_hh & (mask << 32)) >> 32
        h4 = old_hh & mask

        ml = length * 8

        #Pre-processing
        message = wanna_be + pad(length)

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
    print('=========  A user is granting access to the server  =========')
    #user has this message
    mes = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    #user sign it with a common key shared with the server
    old_hh = SHA1(key + mes)
    #user use the message and its signature to the server
    valid = isValid(mes, old_hh)
    if valid:
        print('Welcome back!')
    else:
        print('Invalid signature, please check your information again.')

    print('\n=========  And an attack has retrieve the user\'s message and corresponding hash  =========')
    print(mes)
    print(hex(old_hh).replace('0x','').rjust(40,'0'))

    print('\nNow he will implement the length extension attack on SHA-1 to make a new valid message')
    print('with signature without any knowledge of the secret key itself...')
    
    wanna_be = b';admin=true'
    keyl = -1
    message = b''
    hh = -1
    while not isValid(message, hh):
        keyl += 1
        message = mes + pad(keyl + len(mes)) + wanna_be
        hh = SHA1_LE(old_hh, wanna_be, keyl + len(message))
    print('\nFINALLY!!!!!!!!!!!')
    print('Keyl = ' + str(keyl))
    print(message)
    print(hex(SHA1(key + message)).replace('0x','').rjust(40,'0')) #for demonstration purpose only
    print(hex(hh).replace('0x','').rjust(40,'0'))

if __name__ == '__main__':
    main()
