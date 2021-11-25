import sys
import XORdecoder

f = open('4.txt', 'r')
max_score = -1
best_plain = []
for string in f:
    st = XORdecoder.XOR_decode( string.replace('\n', '') )
    score = XORdecoder.English_score( st )
    if score > max_score:
        max_score = score
        best_plain = [st]
    elif score == max_score:
        best_plain += [st]

for each in best_plain:
    print(each,'\n', max_score)
