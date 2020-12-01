# Random Number Generator | NACTF2020

## Problem
Dr. J created a fast pseudorandom number generator (prng) to randomly assign pairs for the upcoming group test. Austin really wants to know the pairs ahead of time... can you help him and predict the next output of Dr. J's prng?

```python
try:
    with open("flag.txt", "r") as fin:
        flag = fin.read()
except:
    print("Problem is misconfigured - ping us on discord if this is happening on the shell server")
    exit()

import random, time
random.seed(round(time.time() / 100, 5))

print("Welcome to Dr. J's Random Number Generator!")
print("[r] Print a new random number")
print("[g] Guess the next two random numbers and receive the flag!")
print("[q] Quit")


while True:
    inp = input("\n> ")
    if inp == "r":
        print(random.randint(1, 100000000))
    elif inp == "g":
        print("Guess the next two random numbers for a flag!\nGood luck!\nEnter your first guess:")
        if input("> ") == str(random.randint(1, 100000000)):
            print("Wow, lucky guess... You won't be able to guess right a second time\nEnter your second guess:")
            if input("> ") == str(random.randint(1, 100000000)):
                print("What? You must have psychic powers... Well here's your flag: ")
                print(flag)
                break
            else:
                print("That's incorrect. Get out of here!")
                break
        else:
            print("That's incorrect. Get out of here!")
            break
    elif inp == "q":
        print("Goodbye!")
        break
```

## Solution
As the PRNG seed is defined once when a connection is made based on the current system time, the challenge mostly lies in syncing the local time of my machine to that of the server. This is made easier due to the rounding that is occuring, which narrows down how accurate I have to be. I'll retrieve a small set of random values from the program then try a number of different seeds (I went with 1000 seeds both negative and positive) until one is able to produce the same output as the sample from the server.  
Once that occurs, I can make two guesses and get the flag (see solve.py).
```bash
┌──(kali㉿kali)-[~/Desktop/nactf/rng]
└─$ python3 solve.py
Welcome to Dr. J's Random Number Generator!
[r] Print a new random number
[g] Guess the next two random numbers and receive the flag!
[q] Quit

> 
[+] Step 1: Get some "random" numbers...
[+] Step 2: Correct the seed offset...Done.
[+] Step 3: Make guesses...
What? You must have psychic powers... Well here's your flag: 
nactf{ch000nky_turn1ps_1674973}
```