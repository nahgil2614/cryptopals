def fixed_xor( arg1, arg2 ):
    res = ''
    for i in range(len(arg1)):
        res += str( int(arg1[i], 16) ^ int(arg2[i], 16) )
    return res

def main():
    string1 = input('Please enter the first string: ')
    string2 = input('Please enter the second string: ')
    print('XOR combination: ', fixed_xor( string1, string2 ))
    return

if __name__ == '__main__':
    main()
