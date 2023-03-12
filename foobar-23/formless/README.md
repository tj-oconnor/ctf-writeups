# Foobar CTF - Formless

The binary asks the user to input the flag and then performs a check it. The binary then prints out one of two messages depending on if you succeeded our failed.

```
00001a6a      if (check(&var_46, strlen(&var_46)) == 0)
00001a68      {
00001a8a          printf("Conquer the path ahead of you");
00001a89      }
00001a76      else
00001a76      {
00001a76          printf("Empty your mind, be more formles…");
00001a75      }
```

Due to only having two paths, this problem should be fairly easy to model and solve in angr. We load the binary with the angr ``factory.entry_state`` and then execute a simulation, checking the two paths discovered and the input neccessary to produce the output at each path.


```python
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
```

The result shows the path with the flag as the second deadend state input: ``GLUG{bE_W@tER_my_FriEnD}``

```
[+] Loading Angr Project for Formless Challenge
        --0
        [+] Deadend 0: Input = b'\x00\x00\x00\x00...'
        [+] Deadend 0: Output = b'Empty your mind, be more formless'
        --1
        [+] Deadend 1: Input = b'GLUG{bE_W@tER_my_FriEnD}\x00\x00...'
        [+] Deadend 1: Output = b'Conquer the path ahead of you'
```