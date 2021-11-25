max_int = 10**100 - 1
penalty = -1
spaces_percentage = 0.1602766318854647

def English_score( text ):
    ENG_freq = [ 0.08167 , 0.01492 , 0.02202 , 0.04253 , 0.12702 , 0.02228 , 0.02015 ,
          0.06094 , 0.06966 , 0.00153 , 0.01292 , 0.04025 , 0.02406 , 0.06749 ,
          0.07507 , 0.01929 , 0.00095 , 0.05987 , 0.06327 , 0.09356 , 0.02758 ,
          0.00978 , 0.02560 , 0.00150 , 0.01994 , 0.00077 ]
    punc_list = [ 10 , 32 , 33 , 34 , 39 , 40 , 41 , 44 , 45 , 46 , 47 , 58 , 59 ,
                  63 , 64 , 95 ]
    score = 0
    ignore = 0
    punc = 0
    num = 0

    spaces = sum([1 for ltr in text if ltr == ' '])
    
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
    else:
        score = -50

    #percentage of spaces in text:
    if score >= 0.2:
        score += ((spaces / len(text) * spaces_percentage) ** 0.5) * 2.5
    
    return score

def XOR_decode( message ):
    plain = []
    for char in range(256):
        plain += ['']
        for i in range(0, len(message), 2):
            plain[char] += chr(int(message[i:i+2], 16) ^ char)
    max_score = -1
    max_index = -1
    for i in range(256):
        score = English_score(plain[i])
        if score > max_score:
            max_score = score
            max_index = i
    if max_index >= 0:
        return plain[max_index]
    else:
        return '$'

def main():
    string = input('Please enter encoded message: ')
    print( XOR_decode( string ), '\n', English_score(XOR_decode( string )) )

if __name__ == '__main__':
    main()
    
