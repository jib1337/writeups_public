# General Skills Quiz | DUCTF 2021

## Problem
QUIZ TIME! Just answer the questions. Pretty easy right?

Author: Crem
nc pwn-2021.duc.tf 31905 

## Solution
The quiz is timed with 30 seconds on the clock to do some number conversions and decoding.
To complete it in time, I wrote a script to do everything required - see solve.py.

```
┌──(kali㉿kali)-[]-[~/Desktop]
└─$ python3 solve.py
[+] Opening connection to pwn-2021.duc.tf on port 31905: Done
Welcome to the DUCTF Classroom! Cyber School is now in session!
Press enter when you are ready to start your 30 seconds timer for the quiz...
Woops the time is always ticking...
Answer this maths question: 1+1=?

Well I see you are not a bludger then.

Decode this hex string and provide me the original number (base 10): 0x
You're better than a dog's breakfast at least.

Decode this hex string and provide me the original ASCII letter: 
Come on this isn't hard yakka

Decode this URL encoded string and provide me the original ASCII symbols: 
You haven't gone walkabout yet. Keep going!

Decode this base64 string and provide me the plaintext: 
That's a fair crack of the whip.

Encode this plaintext string and provide me the Base64: 
Fair dinkum! That's not bad.

Decode this rot13 string and provide me the plaintext: 
Don't spit the dummy yet!

Encode this plaintext string and provide me the ROT13 equilavent: 
You're sussing this out pretty quickly.

Decode this binary string and provide me the original number (base 10): 0b
Crikey, can you speak computer?

Encode this number and provide me the binary equivalent: 
b"You're better than a bunnings sausage sizzle.\n\nFinal Question, what is the best CTF competition in the universe?\n"
[+] Receiving all data: Done (695B)
[*] Closed connection to pwn-2021.duc.tf port 31905
Bloody Ripper! Here is the grand prize!



   .^.
  (( ))
   |#|_______________________________
   |#||##############################|
   |#||##############################|
   |#||##############################|
   |#||##############################|
   |#||########DOWNUNDERCTF##########|
   |#||########(DUCTF 2021)##########|
   |#||##############################|
   |#||##############################|
   |#||##############################|
   |#||##############################|
   |#|'------------------------------'
   |#|
   |#|
   |#|
   |#|
   |#|
   |#|
   |#|
   |#|
   |#|
   |#|
   |#|
   |#|  DUCTF{you_aced_the_quiz!_have_a_gold_star_champion}
   |#|
   |#|
   |#|   
  //|\\
  ```

