# Psychotic Secrets | WACTF2020

## Problem

Hey C_Sto, we pulled a bunch of secrets from this server and the encryption key, but no IV was stored with them (maybe it's the same for all secrets?)... This feels like a crypto thing, can you help? We know it was encrypted with blowfish CBC. All the ciphertexts seem like they have part of the flag in the first block, with the following block showing you the order to put them in... which sure is handy for a CTF!
```
Key:
omZNZLr5bTA=

Secrets:
maKAexpwttDaw72xqOJvQGVovFyosg9N
jHXHlHxt/I40CA1rAlk2C3NBQh9WP33/
aoT5/dF3XdUMoP93eH4QQvQ0X5Jdc+Sc
vXHyjHuttFCFjT7/MYwhdJOgYFsSuHTQ
PNcJlsbYrdmSUGmJHaYGzJ3NdQ4FHMKf
9QrAQi+OD/JHf6DlZ/CwvdwaOh4gwzZK
```

## Solution
When first attempting to decrypt the secrets with a null IV, it can be seen that the order of the secrets is provided correctly.
```bash
┌──(kali㉿kali)-[~/Desktop/WACTF/crypto2]
└─$ ./solve.py  
b'\xd2s\xd2\xee\x80\x14]=1_accept'
b'\xfcB\xe5\xd5\x99\x06M\x102_access'
b'\xe4Q\xe5\xcf\xa7\x03R63_across'
b'\xee[\xff\xde\xa70V.4_acting'
b'\xf7V\xce\xce\xa90Y*5_action'
b'\xf1m\xe3\xd3\xa1\x07J26_active'
```
However the first block, where the flag parts are is unknown. Assuming they are encrypted with the same IV it is possible to recover this IV by XORing parts of known plaintext against these ciphertext blocks. The known flag plaintext is 'WACTF{' in the first block, so that is where the focus is first. By doing a fixed XOR with `\xd2s\xd2\xee\x80\x14]=` and `WACTF\x00\x00` (two stand-in nulls since we dont know those values yet) we get most of the IV.
```bash
┌──(kali㉿kali)-[~/Desktop/WACTF/crypto2]
└─$ ./solve.py  
Partial flag:
b'WACTF{\x00\x00ypto_i\x10-actual\x0f\x0bkinda_\x0b\x13rd_to_\x04\x17t_righ\x17\x0f'
```
Looking at the resulting plaintext of all the blocks, I can identify the first word past the '{' of the flag to be "crypto". From here we can fully recover the IV and decrypt the full flag (see solve.py).
```bash
┌──(kali㉿kali)-[~/Desktop/WACTF/crypto2]
└─$ ./solve.py  
Partial flag:
b'WACTF{\x00\x00ypto_i\x10-actual\x0f\x0bkinda_\x0b\x13rd_to_\x04\x17t_righ\x17\x0f'

Flag:
WACTF{crypto_is_actuallykinda_hard_to_get_right}
```