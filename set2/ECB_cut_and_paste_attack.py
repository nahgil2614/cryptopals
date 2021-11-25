import base64
import random
import time
import sys

from AES_ECB import KeyExpansion
from AES_ECB import Ciphers
from AES_ECB import InvCiphers
from PKCS7 import PKCS7_pad as pad
from PKCS7 import PKCS7_depad as depad

### My (The attacker's) only hope is that the post-string is actually role=user
### if not, then it's quite impossible to craft the ciphertext

##  Bytes array == bytes type ( b'..' )
##  bytes([3]) => b'\x03'
##  Assume that these encryption things (key, unknown_string) are execute-only, not readable

#const
randKey = [random.getrandbits(8) for i in range(16)]
w = KeyExpansion( randKey )

bytes_list = [bytes([num]) for num in (list(range(97,123)) + list(range(65,91)) + [32,10,33,34,40,41,58,63] + list(range(48,58)))] + [bytes([num]) for num in range(256) if num not in (list(range(97,123)) + list(range(65,91)) + [32,10,33,34,40,41,58,63] + list(range(48,58)))]
#a little improvement, prioritizing by frequency can be even more powerful

############You can only use this thing, in principle###########
def profile_for( your_string ):
    purify = bytes([ltr for ltr in your_string if ltr != ord('&') and ltr != ord('=')]) #get rid of encoding metacharacter
    return Ciphers( pad(b'email=' + purify + b'&uid=10&role=user', 16), w )
#attacker can only feed your_string and receive the cipher, not even the plaintext!

def str2bytes( string ):
    return bytes([ord(ltr) for ltr in string])

def decrypt( string ):
    return depad( str2bytes(InvCiphers( str2bytes(string), w )), 16 )

#repeating '\x00'
def r0( num ):  #r0(-4) == r0(0) == b''
    return bytes(num)

def padOf( num ):
    return bytes([num for i in range(num)])

def main():
    start_time = time.time()
    
    ##  Discover block size and pre + pos's length >>
    feed = b''
    mes = profile_for( feed )
    old_len = len(mes)
    changes_count = 0
    counter = 0
    while (1):
        feed += b'\x00'
        counter += 1
        mes = profile_for( feed )
        if len(mes) != old_len:
            if changes_count == 0:
                prepos_length = old_len - counter  #len(pre + pos)
            old_len = len(mes)
            changes_count += 1
            if changes_count == 2:
                break
            counter = 0
    block_size = counter
    print('Block size: ' + str(block_size))
    print('Pre-string + Post-string\'s length: ' + str(prepos_length))

    ##  Detect if ECB or not  >>
    if block_size == 16:
        ECB_tester = r0(47)
        mes = profile_for( ECB_tester )
        ECB = False
        for i in range(0, len(mes)-16, 16):
            if mes[i:i+16] == mes[i+16:i+32]:
                print('It\'s definitely ECB, bro!')
                ECB = True
                break
        if ECB == False:
            print('Nah, doesn\'t look like ECB to me :v')
            sys.exit()

    ##  Discover len(pre)
    i = 0
    while profile_for(b'')[i:i+16] == profile_for(b'\x00')[i:i+16]:
        i += 16

    num = 1
    new_feed = profile_for(b'\x00')[i:i+16]
    old_feed = profile_for(b'')[i:i+16]
    while new_feed != old_feed:
        num += 1
        old_feed = new_feed
        new_feed = profile_for( r0(num) )[i:i+16]

    pre_pad = num - 1 #r0(pre_pad + ...) + ...
    pre_length = 16 - pre_pad + i
    pos_length = prepos_length - pre_length

    i += 16 #start of a new block
    
    print('Post-string\'s length:', pos_length)

    ##  Check if PKCS#7
    mes = profile_for( r0(16 - prepos_length%16) )[-16:]
    padx10_cipher = profile_for( r0(pre_pad) + padOf(16) )[i:i+16]

    if mes == padx10_cipher:
        print('Probably PKCS#7, sir!')
    else:
        print('It\'s not PKCS#7. I don\'t know what to do next...')
        sys.exit()

    ##  Make sure that the post-string ends with 'user' (attacker's only hope)
    ending_to_check = b'user' #len <= 16
    mes = profile_for( r0(16 - prepos_length%16 + len(ending_to_check)) )[-16:]
    expected_ending_cipher = profile_for( r0(pre_pad) + ending_to_check + padOf(16-len(ending_to_check)) )[i:i+16]

    if mes == expected_ending_cipher:
        print(b'Post-string ends with \'' + ending_to_check + b'\' now let\'s begin!')
    else:
        print(b'Post-string doesn\'t end with \'' + ending_to_check + b'\', don\'t know what to do next...')

    ##  Now change it to admin!
    admin_str = b'admin'
    mail = b'@gmail.com' #len <= 16
    username = bytes([ord('A') for i in range(16 - prepos_length%16 + 16-len(mail) + len(ending_to_check))])
    craft_first = profile_for( username + mail )[:-16]
    craft_second = profile_for( r0(pre_pad) + admin_str + padOf(16-len(admin_str)) )[i:i+16]

    admin_cipher = craft_first + craft_second
    print('\n')
    print(b'Ciphertext for role=admin profile: ' + str2bytes(admin_cipher))
    print(b'Plain: ' + decrypt(admin_cipher))
    
    elapsed_time = time.time() - start_time
    print('Elapsed time (secs):', elapsed_time)

if __name__ == '__main__':
    main()
