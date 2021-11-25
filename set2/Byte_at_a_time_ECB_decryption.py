import base64
import random
import time

from AES_ECB import KeyExpansion
from AES_ECB import Ciphers
from PKCS7 import PKCS7_pad as pad

##  Bytes array == bytes type ( b'..' )
##  bytes([3]) => b'\x03'
##  Assume that these encryption things (key, unknown_string) are execute-only, not readable

#const
randKey = [random.getrandbits(8) for i in range(16)]
w = KeyExpansion( randKey )

highly_likely = [bytes([num]) for num in (list(range(97,123)) + list(range(65,91)) + [32,10,33,34,40,41,58,63] + list(range(48,58)))]
not_likely = [bytes([num]) for num in range(256) if num not in (list(range(97,123)) + list(range(65,91)) + [32,10,33,34,40,41,58,63] + list(range(48,58)))]

def getUnknownString():
    f = open('12.txt', 'r')
    mes = ''
    for line in f:
        mes += line.replace('\n','')
    mes = mes.encode('ascii')
    mes = base64.b64decode( mes )
    return mes

unknown_string = getUnknownString()

############You can only know this thing, in principle###########
def bytesFeed( your_string ):
    return Ciphers( pad(your_string + unknown_string, 16), w )
############You can only know this thing, in principle###########

#repeating A
def rA( num ):  #rA(-4) == rA(0) == b''
    return ''.join(['A' for i in range(num)]).encode('ascii')

def main():
    start_time = time.time()
    
    ##  Discover block size and message's length >>
    feed = b''
    mes = bytesFeed( feed )
    old_len = len(mes)
    changes_count = 0
    counter = 0
    while (1):
        feed += b'A'
        counter += 1
        mes = bytesFeed( feed )
        if len(mes) != old_len:
            if changes_count == 0:
                un_length = old_len - counter
            old_len = len(mes)
            changes_count += 1
            if changes_count == 2:
                break
            counter = 0
    block_size = counter
    print('Block size: ' + str(block_size))
    print('Unknown_string\'s length: ' + str(un_length))

    ##  Detect if ECB or not  >>
    if block_size == 16:
        ECB_tester = rA(32)
        mes = bytesFeed( ECB_tester )
        if mes[:16] == mes[16:32]:
            print('It\'s ECB, bro!')
        else:
            print('Nah, doesn\'t look like ECB to me :v')

    ##  Now let's break it =)  >>

    #Discovery
    D = b''
    
    #   The first round, when D is still empty
    for i in range(16):
        temp_A = rA(15-i)
        mes = bytesFeed( temp_A )[:16]
        added = False
        for temp in highly_likely:
            if bytesFeed(temp_A + D + temp)[:16] == mes:
                D += temp
                print(temp.decode('ascii'), end = '')
                added = True
                break
        if added == False:
            for temp in not_likely:
                if bytesFeed(temp_A + D + temp)[:16] == mes:
                    D += temp
                    print(temp.decode('ascii'), end = '')
                    break
        if len(D) == un_length:
            break

    #   The latter rounds
    if len(D) != un_length:
        for i in range(16, un_length, 16):
            for j in range(16):
                temp_A = rA(15-j)
                mes = bytesFeed( temp_A )[i:i+16]
                added = False
                for temp in highly_likely:
                    if bytesFeed(D[-15:] + temp)[:16] == mes:
                        D += temp
                        print(temp.decode('ascii'), end = '')
                        added = True
                        break
                if added == False:
                    for temp in not_likely:
                        if bytesFeed(D[-15:] + temp)[:16] == mes:
                            D += temp
                            print(temp.decode('ascii'), end = '')
                            break
                if len(D) == un_length:
                    break
    print(D)

    elapsed_time = time.time() - start_time
    print('Elapsed time (secs):', elapsed_time)

if __name__ == '__main__':
    main()
