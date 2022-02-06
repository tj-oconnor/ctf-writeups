
from pwn import *

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
        return remote('ctf.b01lers.com', 9201)
    else:
        return process(e.path)


p = start()
patched_p = process('./gambler-baby1.patched')

while (True):
    try:
        patched_p.recvuntil(b'Correct word: ')
        line = patched_p.recvline().strip(b'\n')
        p.sendline(line)
        print(p.recvline())
    except:
        break
p.interactive()
