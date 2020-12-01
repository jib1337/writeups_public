# Bank Level Crypto | WACTF0x03

## Problem
CC Crypto
We employ military grade crypto within our FinTech TechBank4u™.
To the right is pseudocode of the method we use to secure our valuable Credit Card numbers.
Can you break our XstraSecure© crypto and reveal the username + credit card number of one of our customers, from the ciphertext below:
ODIOBqJDWHAtvLIv8Zk51WcfZFRKDxJ+
```go
func main() {

// Most recent user 
username = 999998
initialKey = "Jsg#kkdf*777" + string(username)
hash = md5(initialkey)

// 2 key in the mode?
finalKey = hash + hash[:8]
iv = []byte{93, 3, 22, 99, 4, 82, 162, 34}

des =  NewCBCTripleDESCipher(finalKey, IV, "pkcs5Padding")
cc = "4444 5555 6666 7777"
encrypted = base64.Encode(des.Encrypt(cc))

if (encrypted == "cL/6j2RHMd95IN2C5vSVcXFu68kcxF4Q"){
	Printf("successfully encrypted")
	}
}
```

## Solution
From the source code it can be seen that the use of the username (which is an incremeting value) as part of the encryption key means there is only a relatively small amount of keys to try, in addition to a fixed IV. The solution is to decrypt the ciphertext using every username's key and using regular expressions to determine when the right result is found (see solve.py).
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ python3 solve.py
Username:        796952
CC Number:       4971 9660 3200 7972
```