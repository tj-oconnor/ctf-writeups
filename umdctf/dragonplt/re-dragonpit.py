from pwn import *
import angr
import logging

logging.getLogger('angr').setLevel(logging.CRITICAL)
logging.getLogger('pwnlib').setLevel(logging.CRITICAL)

e = context.binary = ELF("./dragonpit")

MAIN = e.sym['main']
BAD  = 0x13a4 
GOOD = 0x139a 

p = angr.Project(e.file.name,load_options={'main_opts': {'base_addr': 0}})
s = p.factory.blank_state(addr=MAIN, add_options={angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})

sim = p.factory.simgr(s)
sim.explore(find=GOOD, avoid=BAD)

flag = b''
for i in range(0,20):
   flag += b''+sim.found[0].mem[sim.found[0].regs.rsi+i].char.concrete

print('\n[+] Flag: %s' %flag)
