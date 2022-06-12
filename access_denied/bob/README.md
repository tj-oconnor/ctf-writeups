# Access Denied: Bobs Favourite Number

## Question 

Can you find identify bob's favourite numbers?

server: nc 35.193.60.121 1337


## Solution

Bobs favorite number is the sum of 1856*y+2014*z where y and z are unknown. So we can just iteratively subtract 1856 from the number while number > 1856 and check to see if num %2014 is equal to 0. If so, then its one of bobs favorite numbers and we can return True.

```python
from pwn import *

p = remote('35.193.60.121',1337)

def isFavorite(num):
    
    while num > 1856:
       num -= 1856
       if (num % 2014 == 0):
          return b"Yes"
    return b"No" 


while True:
   num=int(p.recvline())
   print(num)
   p.sendline(isFavorite(num))		
   print(p.recvline())
   print(p.recvline())


p.interactive()

```

Running our script yields the flag 

```
$ python3 bobs_favorite.py

746
b'Answer: \n'
b'Good one\n'
Traceback (most recent call last):
  File "/root/workspace/access_denied/bob/bobs_favorite.py", line 15, in <module>
    num=int(p.recvline())
ValueError: invalid literal for int() with base 10: b'accessdenied{b0bs_f4v0r1t3_numb3r5_4r3_m1n3_f4v0urit3_t00_61c884c8}\n'
```
