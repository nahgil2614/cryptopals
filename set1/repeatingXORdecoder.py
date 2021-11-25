import base64
import math
import sys
import XORdecoder

max_int = 10**100 - 1

def message( base64_message ):
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode( base64_bytes )
    Message = message_bytes.decode('ascii')
    return Message

def normalized_Hamming_dist( string1, string2 ): #assumed that len(str1) == len(str2)
    str1 = ''
    str2 = ''
    for i in range(len(string1)):
        str1 += bin(ord(string1[i])).replace('0b', '').rjust(8, '0')
        str2 += bin(ord(string2[i])).replace('0b', '').rjust(8, '0')
    dist = 0
    for i in range(len(str1)):
        if str1[i] != str2[i]:
            dist += 1
    return dist / len(string1)

def avg_norm_Ham_dist( text, keyl ):
    dist = 0
    count = 0
    for i in range(0, len(text) - 2 * keyl, keyl):
        for j in range(i + keyl, len(text) - keyl, keyl):
            dist += normalized_Hamming_dist( text[i:i+keyl], text[j:j+keyl] )
            count += 1
    return dist / count

def asciiToHex( mes ):
    hex_mes = ''
    for i in mes:
        hex_mes += hex(ord(i)).replace('0x', '').rjust(2, '0')
    return hex_mes

def main():
    f = open('6.txt', 'r')
    Message = ''
    for line in f:
        Message += line.replace('\n', '')
    Message = message( Message )
    min_dist = max_int
    best_keyl = 0
    for keyl in range(2, 41):
        print('Keyl =', keyl)
        dist = avg_norm_Ham_dist( Message, keyl )
        if dist < min_dist:
            min_dist = dist
            best_keyl = keyl
            print('==> Best keyl!!')
    print('Best keyl =', best_keyl)
    texts_with_single_char_key = []
    for i in range(best_keyl):
        texts_with_single_char_key += ['']
        for jumping_collector in range(i, len(Message), best_keyl):
            texts_with_single_char_key[i] += Message[jumping_collector]
        texts_with_single_char_key[i] = XORdecoder.XOR_decode( asciiToHex(texts_with_single_char_key[i]) )

    plain = ''
    for i in range(len(texts_with_single_char_key[0])):
        for j in range(best_keyl):
            if i < len(texts_with_single_char_key[j]):
                plain += texts_with_single_char_key[j][i]

    print(plain)            

if __name__ == '__main__':
    main()
