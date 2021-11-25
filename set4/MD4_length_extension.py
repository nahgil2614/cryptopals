###################################  SERVER'S SIDE  ###################################
#const
mask = 0xffffffff
#bitwise operations have the least priority

#Note 1: all variables are unsigned 32-bit quantities and wrap modulo 2**32 when calculating, except for
    #ml, message length: 64-bit quantity, and
    #hh, message digest: hex string in little-endian
    #little-endian for bytes ordering and big-endian for bits-in-byte

key = b'SuPeR_sEcReT_kEy,_NoT_tO_bE_gUeSsEd_So_EaSiLykhk34j5kj34kltjlk;jkl;jklefj034jijiofjaklwjrkljkljeaef5465456186wa4f65465wa4f561'

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

def isValid( message, hh ):
    res = False
    if MD4(key + message) == hh:
        res = True
    return res

###################################  ATTACKER'S SIDE  ###################################
def pad( bytelength ): #MD_padding
    ml = bytelength * 8

    #Pre-processing
    padding = b'\x80'
    while ((bytelength + len(padding)) * 8) % 512 != 448:
        padding += b'\x00'
    padding += little_endian_64_bit( ml )
    return padding

def MD4_LE(old_hh, wanna_be, length):

    if (len(wanna_be + pad(length)) * 8) % 512 != 0:
        hh = b''
    else:
        #Initialize variable:

        A = sum([int(old_hh[i:i+2], 16) * (256**(i//2)) for i in range(0,8,2)])
        B = sum([int(old_hh[i:i+2], 16) * (256**((i-8)//2)) for i in range(8,16,2)])
        C = sum([int(old_hh[i:i+2], 16) * (256**((i-16)//2)) for i in range(16,24,2)])
        D = sum([int(old_hh[i:i+2], 16) * (256**((i-24)//2)) for i in range(24,32,2)])

        b = length * 8

        #Pre-processing
        message = wanna_be + pad(length)

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
    print('=========  A user is granting access to the server  =========')
    #user has this message
    mes = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    #user sign it with a common key shared with the server
    old_hh = MD4(key + mes)
    #user use the message and its signature to the server
    valid = isValid(mes, old_hh)
    if valid:
        print('Welcome back!')
    else:
        print('Invalid signature, please check your information again.')

    print('\n=========  And an attack has retrieve the user\'s message and corresponding hash  =========')
    print(mes)
    print(old_hh)

    print('\nNow he will implement the length extension attack on MD4 to make a new valid message')
    print('with signature without any knowledge of the secret key itself...')
    
    wanna_be = b';admin=true'
    keyl = -1
    message = b''
    hh = b''
    while not isValid(message, hh):
        keyl += 1
        message = mes + pad(keyl + len(mes)) + wanna_be
        hh = MD4_LE(old_hh, wanna_be, keyl + len(message))
    print('\nFINALLY!!!!!!!!!!!')
    print('Keyl = ' + str(keyl))
    print(message)
    print(MD4(key + message)) #for demonstration purpose only
    print(hh)

if __name__ == '__main__':
    main()
