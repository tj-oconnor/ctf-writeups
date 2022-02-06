import angr, logging
logging.getLogger('angr').setLevel('CRITICAL')

print("[+] Loading Angr Project for Formless Challenge")

p = angr.Project('./chall',main_opts={"base_addr": 0x400000})
state = p.factory.entry_state()
sm = p.factory.simulation_manager(state)

sm.run()

print("\t--0")
print("\t[+] Deadend 0: Input = %s" %sm.deadended[0].posix.dumps(0))
print("\t[+] Deadend 0: Output = %s" %sm.deadended[0].posix.dumps(1))

print("\t--1")
print("\t[+] Deadend 1: Input = %s" %sm.deadended[1].posix.dumps(0))
print("\t[+] Deadend 1: Output = %s" %sm.deadended[1].posix.dumps(1))

