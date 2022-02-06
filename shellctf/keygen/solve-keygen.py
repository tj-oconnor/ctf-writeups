import angr
import sys
from pwn import *
import claripy
import os

GOOD = args.GOOD
BAD  = args.BAD
BASE = 0x400000

def main(argv):
  path_to_binary = args.BIN
  project = angr.Project(path_to_binary, main_opts={"base_addr": BASE})
 

  password_chars = [claripy.BVS("%d" % i, 8) for i in range(20)]
  password_ast = claripy.Concat(*password_chars)

  initial_state = project.factory.entry_state(args=["keygen",password_ast])

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
