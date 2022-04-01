from pwn import *

e = ELF('./babyre0')
print(e.string(e.sym['FLAG']))
