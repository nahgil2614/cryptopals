def PKCS7_pad( mes, block_size ):
    padnum = block_size - len(mes)%block_size
    for i in range( padnum ):
        mes += bytes(chr(padnum), 'utf-8')
    return mes

def PKCS7_depad( mes, block_size ):
    res = mes
    if len(mes) % block_size != 0:
        res = 'out'
    else:
        num = mes[-1]
        for i in range(num):
            if res[-1] != num:
                res = 'out'
                break
            res = res[:-1]
    if res == 'out':
        raise Exception('The string you requested is not well-formatted. Please try again.')
    return res

def valid_pad( mes, block_size ):
    res = mes
    if len(mes) % block_size != 0 or mes[-1] == ord('\x00') or mes[-1] > block_size:
        res = False
    else:
        num = mes[-1]
        for i in range(num):
            if res[-1] != num:
                res = False
                break
            res = res[:-1]
    if res != False:
        res = True
    return res

def main():
    message = bytes(input('Message: '), 'utf-8')
    Block_size = int(input('Block size: '))
    pad = PKCS7_pad(message, Block_size)
    print(pad)
    depad = PKCS7_depad(pad, Block_size)
    print(depad)

if __name__ == '__main__':
    main()
