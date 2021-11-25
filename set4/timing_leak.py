###############################  SERVER'S SIDE  ###############################
import time

mask = 0xffffffff
key = b'SuPeR_sEcReT_kEy,_NoT_tO_bE_gUeSsEd_So_EaSiLy'
opad = bytes([0x5c for _ in range(64)])
ipad = bytes([0x36 for _ in range(64)])

##  The time it takes to perform a round of comparison  >>
sleep_time = 0.001

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
    return hh2bytes(hex(hh).replace('0x','').rjust(40,'0'))

def str2bytes( string ):
    return bytes([ord(ltr) for ltr in string])

def hh2bytes( hh ):
    return bytes([int(hh[i:i+2], 16) for i in range(0, len(hh), 2)])

def XOR2( block1, block2 ):
    return bytes([x^y for x,y in zip(block1, block2)])

def HMAC_SHA1( K, m ):
    if len(K) > 64:
        K = SHA1(K)
    while len(K) != 64:
        K += b'\x00'
    return SHA1(XOR2(K, opad) + SHA1(XOR2(K, ipad) + m))

def bytes2hh( byte ):
    return hex(bytes2int(byte)).replace('0x','').rjust(40,'0')

def insecure_compare( hh, signature ): #both are 20 bytes long
    for i in range(20):
        time.sleep(sleep_time)
        if hh[i] != signature[i]:
            return False
    return True

def isValid( file, signature ):
    return insecure_compare( HMAC_SHA1(key, file), signature )

url = 'http://localhost:9000/test?file=foo&signature=b8b74c284c51a8479522e628c46f772aa57029e7'
url = [string for string in url.split('?') if 'file' in string][0].split('&')
info = [string.split('=')[1] for string in url]

file = str2bytes(info[0])
sig = hh2bytes(info[1])

###############################  ATTACKER'S SIDE  ###############################


def main():
    start_time = time.time()

    print(sig)

    rank = [[] for _ in range(20)]
    time_leak = [[] for _ in range(20)]
    signature = [0 for _ in range(20)]
    index = [0 for _ in range(20)]

    t = 0
    avg_time = 0 #để backtrack hiệu quả hơn
    while t < 20:
        if rank[t] == []:
            #i == 0
            temp = bytes(signature)
            start = time.time()
            isValid(file, temp)
            elapsed = time.time() - start
            rank[t] += [0]
            time_leak[t] += [elapsed]

            for i in range(1, 256):
                signature[t] = i
                temp = bytes(signature)
                start = time.time()
                isValid(file, temp)
                elapsed = time.time() - start

                #insert to temporary rank, time_leak status in descending order
                k = 0
                while time_leak[t][k] > elapsed:
                    k += 1
                    if k == len(time_leak[t]):
                        break
                rank[t] = rank[t][:k] + [i] + rank[t][k:]
                time_leak[t] = time_leak[t][:k] + [elapsed] + time_leak[t][k:]

            #time_leak[t][0] - time_leak[t][-1] < sleep_time
            #nếu max_time là nhanh hết công suất, còn min_time là chậm vì lý do gì đó thì sao??????
            if t == 0:
                avg_time = sum(time_leak[0][1:])/255
                print(avg_time)
                
            elif t != 19 and time_leak[t][0] - sum(time_leak[t][200:])/56 < avg_time * .75: #very unlikely that the last condition is wrong in the right location
                rank[t] = []
                time_leak[t] = []
                signature[t] = 0
                t -= 1
                index[t] += 1
                if index[t] == 256:
                    rank[t] = []
                    time_leak[t] = []
                    signature[t] = 0
                    index[t] = 0
                    t -= 1
                    index[t] += 1
            else:
                signature[t] = rank[t][index[t]]
                t += 1

                print(bytes(signature))
        else:
            signature[t] = rank[t][index[t]]
            t += 1

            print(bytes(signature))

        if t == 20 and not isValid(file, bytes(signature)):
            t -= 1
            index[t] += 1
            if index[t] == 256:
                rank[t] = []
                time_leak[t] = []
                signature[t] = 0
                index[t] = 0
                t -= 1
                index[t] += 1

    print(bytes(signature))

    elapsed_time = time.time() - start_time
    print('Time elapsed: ' + str(elapsed_time))

if __name__ == '__main__':
    main()
