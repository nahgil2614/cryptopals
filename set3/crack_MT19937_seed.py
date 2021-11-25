import time
import random

from MT19937 import seed_mt
from MT19937 import extract_number

def delay( seconds ): #delay thì Ctrl + C được, còn time.sleep() thì không
    start = time.time()
    while time.time() - start < seconds:
        pass

def main():
    start_time = time.time()

    print('Pending...')
    delay(random.randint(40,1000))
    timestamp = int(time.time())
    seed_mt(timestamp)
    rand = extract_number()
    delay(random.randint(40,1000))
    print('\nFirst output of the RNG: ' + str(rand))

    print('\nNow I will try to discover the seed the program has taken')
    print('given the fact that I know it used MT19937!')

    print('\nNow cracking...') 
    test = int(time.time())
    seed_mt(test)
    first = extract_number()
    while first != rand:
        test -= 1
        seed_mt(test)
        first = extract_number()

    print('Haha, the time seed is ' + str(test) + ', isn\'t it?')

    if test == timestamp:
        print('Congratulation! You have broken my super-insecure randomness using timestamp!')
    else:
        print('Huh? That\'s all you have? The real timestamp is ' + str(timestamp))
        print('Poor you.')
    
    time_elapsed = time.time() - start_time
    print('Time elapsed: ' + str(time_elapsed))

if __name__ == '__main__':
    main()
