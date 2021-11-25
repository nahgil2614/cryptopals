def hex_to_base64( hex ):
    alph = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    bits = ''
    for i in range(len(hex)):
        mid = bin(int(hex[i], 16)).replace('0b', '')
        while len(mid) != 4:
            mid = '0' + mid
        bits += mid
    while (len(bits) % 6 != 0):
        bits += '0'
    base64 = ''
    for j in range(0, len(bits), 6):
        base64 += alph[ int( bits[j : j+6], 2) ]
    return base64

def main():
    string = input('Please enter hex string: ')
    print(hex_to_base64(string))
    return

if __name__ == '__main__':
    main()
