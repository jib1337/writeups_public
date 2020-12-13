#!/usr/bin/env python3

from Crypto.Cipher import Blowfish
from unpad import unpad
from base64 import b64decode

key = b64decode('omZNZLr5bTA=')
secrets = [b64decode(b) for b in [
        'maKAexpwttDaw72xqOJvQGVovFyosg9N',
        'jHXHlHxt/I40CA1rAlk2C3NBQh9WP33/', 
        'aoT5/dF3XdUMoP93eH4QQvQ0X5Jdc+Sc', 
        'vXHyjHuttFCFjT7/MYwhdJOgYFsSuHTQ', 
        'PNcJlsbYrdmSUGmJHaYGzJ3NdQ4FHMKf',
        '9QrAQi+OD/JHf6DlZ/CwvdwaOh4gwzZK']]

def decrypt(key, ciphertext, iv='\x00'*8):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), Blowfish.block_size)

def fixedXor(set1, set2):
    return bytes(a ^ b for (a, b) in zip(set1, set2))

# Known plaintext XOR on first block
firstBlock = decrypt(key, secrets[0])[:8]
iv = fixedXor(firstBlock, b'WACTF{\x00\x00')

print(f"Partial flag:\n{b''.join([decrypt(key, s, iv)[:8] for s in secrets])}\n")

# Update the IV and print full flag
iv = fixedXor(firstBlock, b'WACTF{cr')
print(f"Flag:\n{b''.join([decrypt(key, s, iv)[:8] for s in secrets]).decode('utf-8')}")
