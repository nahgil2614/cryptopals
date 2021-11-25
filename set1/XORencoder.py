def XOR_encode( plain, key ):
    message = ''
    for i in range(len(plain)):
        mid = hex(ord(plain[i]) ^ ord(key[ i % len(key)])).replace('0x', '')
        while len(mid) != 2:
            mid = '0' + mid
        message += mid
    return message

def main():
    Plain = input('Enter your plaintext: ')
    Key = input('Enter your key: ')
    print(XOR_encode( Plain, Key ))
    return

if __name__ == '__main__':
    main()
