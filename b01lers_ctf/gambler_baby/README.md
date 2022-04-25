## Question 

Feeling lucky? \

You must create a flag.txt in the same folder as the binary for it to run. \
nc ctf.b01lers.com 9202 \

Author: robotearthpizza \
Difficulty: Easy \

[gambler-baby1](gambler-baby1) \

## Solution

The binary does not properly seed random values. Thus, we can expect the same outcome every time. We patched the original binary to always succeed and then exame all the correct words.

```
./gambler-baby1.patched | grep word
Correct word: nwlr
Correct word: bbmq
Correct word: bhcd
Correct word: arzo
Correct word: wkky
```

Thus, our solution just calls the output from the patched binary and feeds it to the unpatched binary.

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
        return remote('ctf.b01lers.com', 9201)
    else:
        return process(e.path)


p = start()
patched_p = process('./gambler-baby1.patched')

while (True):
    try:
        patched_p.recvuntil(b'Correct word: ')
        line = patched_p.recvline().strip(b'\n')
        p.sendline(line)
        print(p.recvline())
    except:
        break
p.interactive()
```
