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
MT = []
index = n + 1
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

def seed_mt_not_lowest_w_bits( seed ):
    global MT
    global index
    MT = []
    
    index = n
    MT += [seed]
    for i in range(1,n):
        MT += [f * (MT[i-1] ^ (MT[i-1] >> w-2)) + i]

def extract_number_not_lowest_w_bits():
    global MT
    global index
    if index >= n:
        if index > n:
            raise Exception('Generator was never seeded')
            # Alternatively, seed with constant value; 5489 is used in reference C code
        twist()

    y = MT[index]
    y = y ^ ((y >> u) & d)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    y = y ^ (y >> l)

    index = index + 1
    return y

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
    y = y ^ ((y >> u) & d)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    y = y ^ (y >> l)

    index = index + 1
    return y - (y >> w << w) # pretty sure that y is always in 32-bit range,
                             # but this line is just for algorithmical certainty

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

def main():
    start_time = time.time()
    
    for i in range(1000):
        test = []
        seed_mt(i)
        for j in range(n*3):
            test += [extract_number()]

        test_not = [] #Equal!
        seed_mt(i)
        for j in range(n*3):
            test_not += [extract_number_not_lowest_w_bits()]

        #  ==> if the seeding array (n elements) are equal, then the "return y - (y >> w << w)"
        #      at the end of extract_number() is not needed anymore
        #  ==> HOPE FOR WRITING UNTEMPERED FUNCTION

        #test_not = [] #Do not equal!
        #seed_mt_not_lowest_w_bits(i)
        #for j in range(n*3):
        #    test_not += [extract_number_not_lowest_w_bits()]

        #test_not = [] #Do not equal!
        #seed_mt_not_lowest_w_bits(i)
        #for j in range(n*3):
        #    test_not += [extract_number()]
            
        if test == test_not:
            print('Equal!')
        else:
            print('%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n')

    time_elapsed = time.time() - start_time
    print('Time elapsed: ' + str(time_elapsed))

if __name__ == '__main__':
    main()
