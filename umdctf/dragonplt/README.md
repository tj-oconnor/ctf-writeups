## Question 

Fred is trying to learn how to deal with dragons. Can you help him out?

[dragonpit](dragonpit)

## Solution

We are given a binary that has been compiled to run only with GLIBC version 2.34

```
./dragonPit
./dragonPit: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./dragonPit)
```

Rather than patch it, I chose to solve this one symbolically. We see it takes input from stdin and then compares that input at 0x1312. When the user inputs incorrect input, the binary input jumps to 0x13a4. 

```
00001312  e8b9fdffff         call    strcmp
00001317  85c0               test    eax, eax
00001319  0f8585000000       jne     0x13a4
```

On correct input, the program prints out the flag using a format string. We see below that RSI will hold the parameter containing the flag. 

```
....
00001384  488d45c0           lea     rax, [rbp-0x40 {var_48}]
00001388  4889c6             mov     rsi, rax {var_48}
0000138b  488d05a20c0000     lea     rax, [rel data_2034]  {"%.20s\n"}
00001392  4889c7             mov     rdi, rax  {data_2034, "%.20s\n"}
00001395  b800000000         mov     eax, 0x0
0000139a  e811fdffff         call    printf
0000139f  e9ce000000         jmp     0x1472
```

We then wrote a simple script to use angr to symbolically solve for the correct input, stopping at the ```printf``` call at 0x139a. We will then print the character array pointed to by the RSI register. 


```python
from pwn import *
import angr
import logging

logging.getLogger('angr').setLevel(logging.CRITICAL)
logging.getLogger('pwnlib').setLevel(logging.CRITICAL)

e = context.binary = ELF("./dragonpit")

MAIN = e.sym['main']
BAD  = 0x13a4 
GOOD = 0x139a 

p = angr.Project(e.file.name,load_options={'main_opts': {'base_addr': 0}})
s = p.factory.blank_state(addr=MAIN, add_options={angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})

sim = p.factory.simgr(s)
sim.explore(find=GOOD, avoid=BAD)

flag = b''
for i in range(0,20):
   flag += b''+sim.found[0].mem[sim.found[0].regs.rsi+i].char.concrete

print('\n[+] Flag: %s' %flag)
```

Running the program yields our flag.

```
 python3 re-dragonpit.py

[+] Flag: b'UMDCTF{BluSt0l3dr4g}'
```