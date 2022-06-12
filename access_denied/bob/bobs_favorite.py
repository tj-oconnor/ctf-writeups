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

