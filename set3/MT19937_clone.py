# Today, I have learned to use global keyword
# in order to make change to a global variable inside a function

import time

#mersenne_twister_engine (32-bit)
#it means that the output number always stay in the 32-bit range, not 64 like MT19937-64
w = 32
n = 624
m = 397
r = 31
a = 0x9908b0df
u = 11
d = 0xffffffff
s = 7
b = 0x9d2c5680
t = 15
c = 0xefc60000
l = 18
f = 1812433253

# Create a length n array to store the state of the generator
# _c stands for _clone
MT = []
MT_c = []
index = n + 1
index_c = n
lower_mask = (1 << r) - 1 # That is, the binary number of r 1's
upper_mask = (1 << w-r) - 1 << r

# Initialize the generator from a seed
def seed_mt( seed ):
    global MT
    global index
    MT = []
    
    index = n
    MT += [seed]
    for i in range(1,n):
        MT += [f * (MT[i-1] ^ (MT[i-1] >> w-2)) + i]
        MT[i] = MT[i] - (MT[i] >> w << w) # Lowest w bits of MT[i]

# Extract a tempered value based on MT[index]
# calling twist() every n numbers
def extract_number():
    global MT
    global index
    if index >= n:
        if index > n:
            raise Exception('Generator was never seeded')
            # Alternatively, seed with constant value; 5489 is used in reference C code
        twist()

    y = MT[index]
    y = y ^ ((y >> u) & d) #Right1
    y = y ^ ((y << s) & b) #Left
    y = y ^ ((y << t) & c) #Left
    y = y ^ (y >> l)       #Right2

    index = index + 1
    return y - (y >> w << w) # pretty sure that y is always in 32-bit range,
                             # but this line is just for algorithmical certainty    

def unRight1(y, x, z):
    y = [ord(ltr)-48 for ltr in bin(y).replace('0b','')]
    z = [ord(ltr)-48 for ltr in bin(z).replace('0b','')]
    for i in range(x, len(y)):
        z_i = 0
        if i - len(y) >= -len(z):
            z_i = z[i-len(y)]
        y[i] = y[i] ^ (y[i-x] & z_i)
    return int(''.join([chr(bit+48) for bit in y]), 2)
    
def unRight2(y, x):
    y = [ord(ltr)-48 for ltr in bin(y).replace('0b','')]
    for i in range(x, len(y)):
        y[i] = y[i] ^ y[i-x]
    return int(''.join([chr(bit+48) for bit in y]), 2)

def unLeft(y, x, z):
    z = [ord(ltr)-48 for ltr in bin(z).replace('0b','')]
    y = [ord(ltr)-48 for ltr in bin(y).replace('0b','').rjust(len(z),'0')]
    for i in range(-1-x, -len(z) - 1, -1):
        y[i] = y[i] ^ (y[i+x] & z[i])
    return int(''.join([chr(bit+48) for bit in y]), 2)

def untemper( y ):
    y = unRight2(y, l)
    y = unLeft(y, t, c)
    y = unLeft(y, s, b)
    y = unRight1(y, u, d)
    return y

# Generate the next n values from the series x_i
def twist():
    global MT
    global index
    for i in range(n):
        x = (MT[i] & upper_mask)
        + (MT[(i+1) % n] & lower_mask)
        xA = x >> 1
        if (x % 2) != 0: # lowest bit of x is 1
            xA = xA ^ a
        MT[i] = MT[(i+m) % n] ^ xA
    index = 0

def extract_number_c():
    global MT_c
    global index_c
    if index_c == n:
        twist_c()

    y = MT_c[index_c]
    y = y ^ ((y >> u) & d) #Right1
    y = y ^ ((y << s) & b) #Left
    y = y ^ ((y << t) & c) #Left
    y = y ^ (y >> l)       #Right2

    index_c += 1
    return y - (y >> w << w)

def twist_c():
    global MT_c
    global index_c
    for i in range(n):
        x = (MT_c[i] & upper_mask)
        + (MT_c[(i+1) % n] & lower_mask)
        xA = x >> 1
        if (x % 2) != 0: # lowest bit of x is 1
            xA = xA ^ a
        MT_c[i] = MT_c[(i+m) % n] ^ xA
    index_c = 0

def main():
    start_time = time.time()

    global MT_c
    seed_mt(int(time.time()))
    rand_pre = extract_number() % 1000
    print('The server is producing random numbers...')
    for _ in range(rand_pre):
        extract_number()
        #print(extract_number())
        
    print('******  Begin tapping for ' + str(n) + ' outputs...  ******')
    time.sleep(1)
    for _ in range(n):
        temp = extract_number()
        MT_c += [untemper(temp)]
        #print(temp)
    print('DONE!')
    time.sleep(.5)
    print('******  Begin guessing...  ******')
    time.sleep(1)

    equal = True
    for _ in range(1000000):
        #print(extract_number())
        #print(extract_number_c())
        #print('\n')
        if extract_number() != extract_number_c():
            equal = False
            break
    if equal:
        print('Congrats! You have guessed all my outputs right!')
    else:
        print('Haha have you missed something?')

    time_elapsed = time.time() - start_time
    print('Time elapsed: ' + str(time_elapsed))

if __name__ == '__main__':
    main()
