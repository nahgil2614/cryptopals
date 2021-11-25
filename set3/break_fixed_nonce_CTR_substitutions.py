import random
import time
import base64

from AES_CTR import CTR
from AES_CBC import KeyExpansion

#const
nonce = 0
randKey = bytes([random.getrandbits(8) for i in range(16)])
w = KeyExpansion( randKey )
IV = ''.join(['\x00' for i in range(16)])
bytes_list = [bytes([i]) for i in range(256)]

def English_score( text ):
    ENG_freq = [ 0.08167 , 0.01492 , 0.02202 , 0.04253 , 0.12702 , 0.02228 , 0.02015 ,
          0.06094 , 0.06966 , 0.00153 , 0.01292 , 0.04025 , 0.02406 , 0.06749 ,
          0.07507 , 0.01929 , 0.00095 , 0.05987 , 0.06327 , 0.09356 , 0.02758 ,
          0.00978 , 0.02560 , 0.00150 , 0.01994 , 0.00077 ]
    punc_list = [ 10 , 32 , 33 , 34 , 39 , 40 , 41 , 44 , 45 , 46 , 47 , 58 , 59 ,
                  63 , 64 , 95 ]
    spaces_percentage = 0.1602766318854647
    
    score = 0
    ignore = 0
    punc = 0
    num = 0

    spaces = text.count(' ')
    
    for i in text:
        if ord(i) in punc_list :
            punc += 1
        elif ord(i) in range(48,58):
            num += 1
        elif ord(i) not in range(65,91) and ord(i) not in range(97,123):
            ignore += 1

    length = len(text) - ignore - punc - num
    if length != 0 and ignore == 0:
        for i in range(len(ENG_freq)):
            score += ((text.count(chr(i + 97)) + text.count(chr(i + 65))) / length * ENG_freq[i]) ** 0.5
        score *= length / len(text) #the more letters, the more scores
    else:
        score = -50

    #percentage of spaces in text:
    if score >= 0.2:
        score += ((spaces / len(text) * spaces_percentage) ** 0.5) * 2.5
    
    return score

def bunch_of_ciphertexts():
    res = []
    f = open('19.txt', 'r')
    for line in f:
        res += [CTR( base64.b64decode(line.replace('\n','').encode('ascii')), nonce, w, IV )]
    return res

#return a number
def XOR( block1, block2 ):
    res = bytes([x^y for x,y in zip(block1,block2)])
    if res == b'':
        res = b' '
    return ord(res)
    
def main():
    start_time = time.time()

    guessed_keystream = b''
    ciphers = bunch_of_ciphertexts()

    max_cipher_length = max([len(cipher) for cipher in ciphers])
    plains = ['' for i in range(len(ciphers))]

    for cipher_no in range(max_cipher_length):
        max_score = -100
        best_plain = []
        for key in bytes_list:
            plain = [chr(XOR(ciphers[i][cipher_no:cipher_no+1], key)) for i in range(len(ciphers))]
            score = English_score(plain)
            if score > max_score:
                max_score = score
                best_plain = plain

        count = 0
        for i in best_plain:
            plains[count] += i
            count += 1
            print(i, end = ' ')
        print('\n')

    for i in range(len(plains)):
        print( str(i).rjust(2,'0') + '. ' + plains[i] )
    
    elapsed_time = time.time() - start_time
    print('Time elapsed: ' + str(elapsed_time))

if __name__ == '__main__':
    main()
