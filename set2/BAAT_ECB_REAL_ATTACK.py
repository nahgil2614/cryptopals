import base64
import random
import time
import sys

from AES_ECB import KeyExpansion
from AES_ECB import Ciphers
from PKCS7 import PKCS7_pad as pad

##  Bytes array == bytes type ( b'..' )
##  bytes([3]) => b'\x03'
##  Assume that these encryption things (key, unknown_string) are execute-only, not readable

#const
random_prefix = bytes([random.getrandbits(8) for i in range(random.randint(13,50))])
randKey = [random.getrandbits(8) for i in range(16)]
w = KeyExpansion( randKey )

bytes_list = [bytes([num]) for num in (list(range(97,123)) + list(range(65,91)) + [32,10,33,34,40,41,58,63] + list(range(48,58)))] + [bytes([num]) for num in range(256) if num not in (list(range(97,123)) + list(range(65,91)) + [32,10,33,34,40,41,58,63] + list(range(48,58)))]
#a little improvement, prioritizing by frequency can be even more powerful

def getUnknownString():
    f = open('12.txt', 'r')
    mes = ''
    for line in f:
        mes += line.replace('\n','')
    mes = mes.encode('ascii')
    mes = base64.b64decode( mes )
    return mes

unknown_string = b'&uid=10&role=user'#getUnknownString()

############You can only know this thing, in principle###########
def bytesFeed( your_string ):
    return Ciphers( pad(random_prefix + your_string + unknown_string, 16), w )
############You can only know this thing, in principle###########

#repeating '\x00'
def r0( num ):  #r0(-4) == r0(0) == b''
    return bytes(num)

def main():
    start_time = time.time()
    
    ##  Discover block size and random-prefix + unknown-string's length >>
    feed = b''
    mes = bytesFeed( feed )
    old_len = len(mes)
    changes_count = 0
    counter = 0
    while (1):
        feed += b'\x00'
        counter += 1
        mes = bytesFeed( feed )
        if len(mes) != old_len:
            if changes_count == 0:
                randun_length = old_len - counter  #len(rand + un)
            old_len = len(mes)
            changes_count += 1
            if changes_count == 2:
                break
            counter = 0
    block_size = counter
    print('Block size: ' + str(block_size))
    print('Random-prefix + Unknown_string\'s length: ' + str(randun_length))

    ##  Detect if ECB or not  >>
    if block_size == 16:
        ECB_tester = r0(47)
        mes = bytesFeed( ECB_tester )
        ECB = False
        for i in range(0, len(mes)-16, 16):
            if mes[i:i+16] == mes[i+16:i+32]:
                print('It\'s definitely ECB, bro!')
                ECB = True
                break
        if ECB == False:
            print('Nah, doesn\'t look like ECB to me :v')
            sys.exit()

    ##  Discover len(rand)
    i = 0
    while bytesFeed(b'')[i:i+16] == bytesFeed(b'\x00')[i:i+16]:
        i += 16

    num = 1
    new_feed = bytesFeed(b'\x00')[i:i+16]
    old_feed = bytesFeed(b'')[i:i+16]
    while new_feed != old_feed:
        num += 1
        old_feed = new_feed
        new_feed = bytesFeed( r0(num) )[i:i+16]

    rand_pad = num - 1 #r0(rand_pad + ...) + ...
    rand_length = 16 - rand_pad + i
    un_length = randun_length - rand_length

    i += 16 #start of a new block

    print('Unknown-string\'s length:', un_length)

    ##  Now let's break it =)  >>

    #Discovery
    D = b''
    
    #   The first round, when D is still empty
    for t in range(16):
        temp_0 = r0(rand_pad + 15-t)
        mes = bytesFeed( temp_0 )[i:i+16]
        for temp in bytes_list:
            if bytesFeed(temp_0 + D + temp)[i:i+16] == mes:
                D += temp
                print(temp.decode('ascii'), end = '')
                break
        if len(D) == un_length:
            break

    #   The latter rounds
    t = 16 + i
    while len(D) != un_length:
        for j in range(16):
            temp_0 = r0(rand_pad + 15-j)
            mes = bytesFeed( temp_0 )[t:t+16]
            for temp in bytes_list:
                if bytesFeed(r0(rand_pad) + D[-15:] + temp)[i:i+16] == mes:
                    D += temp
                    print(temp.decode('ascii'), end = '')
                    break
            if len(D) == un_length:
                break
        t += 16
        
    print(D)

    elapsed_time = time.time() - start_time
    print('Elapsed time (secs):', elapsed_time)

if __name__ == '__main__':
    main()
