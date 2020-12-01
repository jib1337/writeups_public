'''
CC Crypto
We employ military grade crypto within our FinTech TechBank4u™.
To the right is pseudocode of the method we use to secure our valuable Credit Card numbers.
Can you break our XstraSecure© crypto and reveal the username + credit card number of one of our customers, from the ciphertext below:
ODIOBqJDWHAtvLIv8Zk51WcfZFRKDxJ+

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
'''

import base64, array, hashlib, re
from Crypto.Cipher import DES3

iv = array.array('B', [93, 3, 22, 99, 4, 82, 162, 34]).tostring()
message = "4444 5555 6666 7777"
initialKey1 = "Jsg#kkdf*777"
username = '999998' #999998

def encryptDES3(key, message, iv):

	message = pad(message).encode('UTF-8')
	des = DES3.new(key, DES3.MODE_CBC, iv)

	return base64.b64encode(des.encrypt(message)).decode('utf-8')

def decryptDES3(key, message, iv):

	des = DES3.new(key, DES3.MODE_CBC, iv)

	return unpad(des.decrypt(base64.b64decode(message)).decode('utf-8', 'replace'))

def constructKey(initialKey1, username):
	unhashedkey = initialKey1 + str(username)
	m = hashlib.md5()
	m.update(unhashedkey.encode('utf-8'))
	hashedkey = m.digest()

	return(hashedkey + hashedkey[:8])

# PKCS5 pad
BS = 8
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

# Test values
# print(encryptDES3(constructKey(initialKey1, username), message, iv))
# print(decryptDES3(constructKey(initialKey1, username), 'cL/6j2RHMd95IN2C5vSVcXFu68kcxF4Q', iv))
# print(encryptDES3(constructKey(initialKey1, '32432'), '4445 6665 4564 3243', iv))

regex = '[0-9]{4}\s[0-9]{4}\s[0-9]{4}\s[0-9]{4}'
unknownmessage = 'ODIOBqJDWHAtvLIv8Zk51WcfZFRKDxJ+'

for i in range(0, 999998):

	username = i
	output = decryptDES3(constructKey(initialKey1, username), unknownmessage, iv)

	if re.search(regex, output):
		print('Username:\t', username)
		print('CC Number:\t', output)
		break