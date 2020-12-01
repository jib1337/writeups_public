import socket, random, time

def getRandom():
    s.send(b'r\n')
    return int(s.recv(4096).decode('utf-8').split()[0])

def guess():
    s.send(b'g\n')
    s.recv(4096)
    s.send(bytes(str(random.randint(1, 100000000)) + '\n', 'utf-8'))
    s.recv(4096)
    s.send(bytes(str(random.randint(1, 100000000)) + '\n', 'utf-8'))
    return(s.recv(4096).decode('utf-8'))


s = socket.socket()
s.connect(("challenges.ctfd.io",30264))
base = time.time()
info = s.recv(4096).decode("utf-8")
print(info)

print('[+] Step 1: Get some "random" numbers...')

# Get 10 random numbers to use for syncing
randints = [getRandom() for i in range(10)]

print('[+] Step 2: Correct the seed offset...', end='')

# Bruteforce the PRNG
found = False
for offset in range(-500, 500):
    
    if found:
        break

    random.seed(round((base + (offset / 1000)) / 100, 5))

    correct = 0
    for i in randints:
        if random.randint(1, 100000000) == i:
            correct += 1
            if correct == 10:
                found = True
                print('Done.')
                break
        else:
            break

if not found:
    print('Fail.')
    quit()
else:
    print('[+] Step 3: Make guesses...')
    print(guess())
