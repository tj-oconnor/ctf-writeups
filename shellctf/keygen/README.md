# Keygen

## Description

Enter the license key and get the flag.Simple right ? 
Flag Format:SHELLCTF{}.

## Files

* [keygen](keygen)

## Solution

```
00001383  488d3d900c0000     lea     rdi, [rel data_201a]  {"Access Granted!:%s"}
0000138a  b800000000         mov     eax, 0x0
0000138f  e80cfdffff         call    printf
00001394  eb1f               jmp     0x13b5

00001396  488d3d900c0000     lea     rdi, [rel data_202d]  {"Wrong!!!"}
0000139d  b800000000         mov     eax, 0x0
000013a2  e8f9fcffff         call    printf
000013a7  eb0c               jmp     0x13b5
```

```
import angr
import sys
from pwn import *
import claripy
import os

GOOD = 'Granted'
BAD  = 'Wrong'
BASE = 0x400000

def main(argv):
  path_to_binary = args.BIN
  project = angr.Project(path_to_binary, main_opts={"base_addr": BASE})
 

  password_chars = [claripy.BVS("%d" % i, 8) for i in range(20)]
  password_ast = claripy.Concat(*password_chars)

    # pass the symbolic variable representing the password as argv[1]

  initial_state = project.factory.entry_state(args=["keygen",password_ast])
  #  add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
  #                  angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
  #)

  for k in password_chars:
       initial_state.solver.add(k <= 0x7f)
       initial_state.solver.add(k >= 0x20)

  simulation = project.factory.simgr(initial_state)

  def good_path(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return GOOD.encode() in stdout_output  

  def bad_path(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return BAD.encode() in stdout_output 

  simulation.explore(find=good_path, avoid=bad_path)

  if simulation.found:
    found_password = simulation.found[0].solver.eval(password_ast, cast_to = bytes)
    print("License: {%s}" %found_password)

  else:
    print("No solution found")

if __name__ == '__main__':
  main(sys.argv)
```