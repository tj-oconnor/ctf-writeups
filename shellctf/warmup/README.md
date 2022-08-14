# warmup

## Description

Here's a quick rev challenge to get started. Reverse the binary to obtain the flag.

The flag format is shellctf{...}

## Files

* [warmup](warmup)

## Solution

```python
import angr
import sys
from pwn import *

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
    return b'yes' in stdout_output  

  def bad_path(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return ((b'nah' in stdout_output) or (b'wrong' in stdout_output))

  simulation.explore(find=good_path, avoid=bad_path)

  if simulation.found:
    print("Solution: {%s}" %simulation.found[0].posix.dumps(sys.stdin.fileno()))

if __name__ == '__main__':
  main(sys.argv)
```