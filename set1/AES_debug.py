import base64
from copy import deepcopy

#REMEMBER TO A = B[:] TO GET ONLY THE VALUE, NOT THE POINTER
#BUT IT'S NOT WORKING FOR 2D ARRAY SO YOU HAVE TO USE DEEPCOPY
#OR A = [ROW[:] FOR ROW IN ARRAY]

#This program treat each byte as an integer

S_box = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]

Rcon = [ 0 ,
         [ 1 , 0 , 0 , 0 ] ,
         [ 2 , 0 , 0 , 0 ] ,
         [ 4 , 0 , 0 , 0 ] ,
         [ 8 , 0 , 0 , 0 ] ,
         [ 16 , 0 , 0 , 0 ] ,
         [ 32 , 0 , 0 , 0 ] ,
         [ 64 , 0 , 0 , 0 ] ,
         [ 128 , 0 , 0 , 0 ] ,
         [ 27 , 0 , 0 , 0 ] ,
         [ 54 , 0 , 0 , 0 ] ]

#InvMixColumnsMatrix
IMCM = [ [ 14 , 11 , 13 , 9 ] ,
         [ 9 , 14 , 11 , 13 ] ,
         [ 13 , 9 , 14 , 11 ] ,
         [ 11 , 13 , 9 , 14 ] ]

empty_block = [ [0,0,0,0] ,
                [0,0,0,0] ,
                [0,0,0,0] ,
                [0,0,0,0] ]

def AddWord( word1, word2 ):
    return [ x^y for x,y in zip(word1,word2) ]

def xtime( byte ):
    res = byte * 2
    if byte >= 128:
        res -= 256
        res ^= 27
    return res

def Multiply( byte1, byte2 ):
    res = 0
    temp = byte1
    sup = 0
    power = [ 7-i for i,bit in enumerate(bin(byte2).replace('0b', '').rjust(8, '0')) if bit == '1']
    power = power[::-1] #IT FLIPS THE ARRAY!!! OMG :))
    for i in power:
        for j in range(sup,i):
            temp = xtime( temp )
        sup = i
        res ^= temp
    return res

def SubByte( byte ):
    return [y for x,y in enumerate(S_box) if x == byte][0]
    
def SubWord( word ):
    return [ SubByte( i ) for i in word ]

def RotWord( word ):
    return [word[(i+1)%4] for i in range(4)]

def KeyExpansion( key ):
    w = []
    for i in range(4):
        w += [ [key[i*4], key[i*4+1], key[i*4+2], key[i*4+3]] ]
    for i in range(4, 4*(10+1)):
        temp = w[i-1]
        if i%4 == 0:
            temp = AddWord( SubWord(RotWord(temp)) , Rcon[i//4] )
        w += [ AddWord( w[i-4] , temp ) ]
    w1 = [''.join([hex(w[c][r]).replace('0x','').rjust(2,'0') for r in range(4)])for c in range(len(w))]
    print(w1)
    return w

def InvShiftRows( block ):
    return [ [ block[r][(c+4-r) % 4] for c in range(4) ] for r in range(4) ]

def InvSubByte( byte ):
    return [x for x,y in enumerate(S_box) if y == byte][0]

def InvSubBytes( block ):
    return [ [ InvSubByte( block[r][c] ) for c in range(4) ] for r in range(4) ]

def InvMixColumns( block ):
    #temp_block = block[:] #ONLY COPY THE VALUE, NOT THE ENTIRE POINTER
    temp_block = deepcopy(empty_block)
    print('In IMC: ' + display(empty_block) + ' ' + display(temp_block))
    for c in range(4):
        for r in range(4):
            for col in range(4):
                print('IMCB_' + str(c) + str(r) + str(col) + ': ' + display(temp_block))
                temp_block[r][c] ^= Multiply( IMCM[r][col], block[col][c] )
    return temp_block

def AddRoundKey( block, key ):
    temp_block = deepcopy(empty_block)
    print('In ARK: ' + display(empty_block) + ' ' + display(temp_block))
    for c in range(4):
        temp = AddWord( [block[0][c] , block[1][c] , block[2][c] , block[3][c]] , key[c] )
        for r in range(4):
            temp_block[r][c] = temp[r]
    return temp_block                

def getMessage():
    f = open('7.txt', 'r')
    mes = ''
    for line in f:
        mes += line.replace('\n', '')
    mes = mes.encode('ascii')
    mes = base64.b64decode( mes )
    return mes

def display( block ):
    res = [ '' , '' , '' , '' ,
            '' , '' , '' , '' ,
            '' , '' , '' , '' ,
            '' , '' , '' , '' ]
    for r in range(4):
        for c in range(4):
            res[r+4*c] = hex(block[r][c]).replace('0x','').rjust(2,'0')
    res = ''.join(res)
    return res   

def InvCipher( string_chunk, w ):

    round_ = 10
    block = [[string_chunk[r+4*c] for c in range(4)] for r in range(4)]
    print('round[' + str(10-round_).rjust(2,' '),'].iinput   ' + display(block))
    block = AddRoundKey( block, w[40:] )
    print('round[' + str(10-round_).rjust(2,' '),'].ik_sch   ' + display(w[40:]))
    
    for round_ in range(9,0,-1):
        print('round[' + str(10-round_).rjust(2,' '),'].istart   ' + display(block))
        block = InvShiftRows(block)
        print('round[' + str(10-round_).rjust(2,' '),'].is_row   ' + display(block))
        block = InvSubBytes(block)
        print('round[' + str(10-round_).rjust(2,' '),'].is_box   ' + display(block))
        block = AddRoundKey( block, w[round_*4 : round_*4+4] )
        print('round[' + str(10-round_).rjust(2,' '),'].ik_sch   ' + display(w[round_*4 : round_*4+4]))
        print('round[' + str(10-round_).rjust(2,' '),'].ik_add   ' + display(block))
        block = InvMixColumns(block)

    round_ = 0
    block = InvShiftRows(block)
    block = InvSubBytes(block)
    block = AddRoundKey(block, w[:4])

    res = [ '' , '' , '' , '' ,
            '' , '' , '' , '' ,
            '' , '' , '' , '' ,
            '' , '' , '' , '' ]
    for r in range(4):
        for c in range(4):
            res[r+4*c] = chr(block[r][c])
    return res

def main():
    #message = getMessage()
    mes = []
    message = input('Message: ')
    for i in range(0, len(message), 2):
        mes += [int(message[i:i+2], 16)]
    message = mes

    #key = b'YELLOW SUBMARINE'
    key = input('Key: ')
    mes = []
    for i in range(0, len(key), 2):
        mes += [int(key[i:i+2], 16)]
    key = mes
    #########
    w = KeyExpansion( key )

    plain = []
    
    for i in range(0, len(message), 16):
        plain += InvCipher( message[i:i+16], w )

    #########
    pl = ''
    for i in plain:
        pl += hex(ord(i)).replace('0x','').rjust(2,'0')
    plain = pl
    #########

    print(plain)

if __name__ == '__main__':
    while(1):
        main()
