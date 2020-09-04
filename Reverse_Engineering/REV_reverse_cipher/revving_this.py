#!/usr/bin/env python3

with open('rev_this', 'r') as flagFile:
    flag = flagFile.read().rstrip('\n')

print(flag[:8], end='')

for i, byte in enumerate(flag[8:-2]):
    if i & 1 == 0:
        print(chr(ord(byte)-5), end='')
    else:
        print(chr(ord(byte)+2), end='')

print(flag[-1])
