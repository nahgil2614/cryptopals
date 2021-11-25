f = open('8.txt', 'r')
mes = []
overlapped = False
for line in f:
    line = line.replace('\n','')
    for i in range(0, len(line), 32):
        overlapped = False
        for sub in mes:
            if line[i:i+32] == sub:
                overlapped = True
                print(sub)
                break
        if not overlapped:
            mes += [line[i:i+32]]
