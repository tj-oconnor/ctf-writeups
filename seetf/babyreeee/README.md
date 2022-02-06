# babyree

# Challenge

[chall](chall)

# Solution

The binary is a fairly simply program that either prints ``Success!`` or ``wrong`` upon the correct/incorrect input. I decided that I've seen enough similar problems to just make a generic script to solve this type of problem.

```python
import angr
import sys
from pwn import *

GOOD = args.GOOD
BAD  = args.BAD
BASE = 0x400000

def main(argv):
  path_to_binary = args.BIN

  project = angr.Project(path_to_binary, main_opts={"base_addr": BASE})
  initial_state = project.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
  )
  simulation = project.factory.simgr(initial_state)

  def good_path(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return GOOD.encode() in stdout_output  

  def bad_path(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return BAD.encode() in stdout_output 

  simulation.explore(find=good_path, avoid=bad_path)

  if simulation.found:
    print("Solution: {%s}" %simulation.found[0].posix.dumps(sys.stdin.fileno()))

if __name__ == '__main__':
  main(sys.argv)
```

Runnign the script, setting the binary to ``chall`` with with ``GOOD="Success"`` and ``BAD="wrong"`` yields the following solution.

```
python3 re-chall.py BIN=./chall GOOD="Success" BAD="wrong"
Solution: {b'SEE{0n3_5m411_573p_81d215e8b81ae10f1c08168207fba396}@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\>
```
