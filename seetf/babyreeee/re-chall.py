
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
