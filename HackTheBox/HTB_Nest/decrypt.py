#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
from base64 import b64decode

# Decrypt(EncryptedString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)

ciphertext = b64decode('fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=')
passphrase = 'N3st22'.encode('utf-8')
saltValue = '88552299'.encode('utf-8')
iterations = 2
initVector = '464R5DFA5DL6LE28'.encode('utf-8')

password = PBKDF2(passphrase, saltValue, count=iterations, dkLen=32)

cipher = AES.new(password, AES.MODE_CBC, initVector)
plaintext = unpad(cipher.decrypt(ciphertext), 16).decode('utf-8')
print(plaintext)