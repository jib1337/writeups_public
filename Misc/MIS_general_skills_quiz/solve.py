#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host pwn-2021.duc.tf --port 31905
import codecs
from binascii import unhexlify as unhex
from urllib.parse import unquote
from base64 import b64decode, b64encode
from pwn import *

host = args.HOST or 'pwn-2021.duc.tf'
port = int(args.PORT or 31905)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    return remote(argv, *a, **kw)


#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

print(io.sendlineafter('...', '\r').decode('utf-8'))
print(io.sendlineafter('?', '2').decode('utf-8'))

# solve hex value
print(io.recvuntil('0x').decode('utf-8'))
var = io.recvline().rstrip(b'\n').decode('utf-8')
io.sendline(str(int(var, 16)))

# solve ascii value
print(io.recvuntil('ASCII letter: ').decode('utf-8'))
var = io.recvline().rstrip(b'\n').decode('utf-8')
io.sendline(unhex(var))

# solve ascii symbols
print(io.recvuntil('ASCII symbols: ').decode('utf-8'))
var = io.recvline().rstrip(b'\n').decode('utf-8')
io.sendline(unquote(var))

# base64 text decode
print(io.recvuntil('plaintext: ').decode('utf-8'))
var = io.recvline().rstrip(b'\n').decode('utf-8')
io.sendline(b64decode(var))

# base64 text encode
print(io.recvuntil('Base64: ').decode('utf-8'))
var = io.recvline().rstrip(b'\n')
io.sendline(b64encode(var))

# rot13 decode
print(io.recvuntil('plaintext: ').decode('utf-8'))
var = io.recvline().rstrip(b'\n').decode('utf-8')
io.sendline(codecs.decode(var, 'rot-13'))

# rot13 encode
print(io.recvuntil('equilavent: ').decode('utf-8'))
var = io.recvline().rstrip(b'\n').decode('utf-8')
io.sendline(codecs.encode(var, 'rot-13'))

# binary decode
print(io.recvuntil('(base 10): 0b').decode('utf-8'))
var = io.recvline().rstrip(b'\n').decode('utf-8')
io.sendline(str(int(var, 2)))

# binary encode
print(io.recvuntil('equivalent: ').decode('utf-8'))
var = int(io.recvline().rstrip(b'\n').decode('utf-8'))
io.sendline(str(bin(var)))

# whats the best ctf
print(io.sendlineafter('universe?\n', 'DUCTF'))
print(io.recvall().decode('utf-8'))
