"""
Compile and execute a small program to get the value of certain glibc
constants.
"""

import json
import logging
import os
import subprocess
import sys
import tempfile

# A very simple c-program to print the value of certain glibc
# constants for the current system.
GET_CONSTANTS_PROGRAM = r"""
#include <sched.h>
#include <stdio.h>
#include <sys/mount.h>

#define PRINT_CONST(X) printf("  \"%s\" : %x,\n", #X, X)

int main(int argc, char** argv) {
    printf("{\n");
    PRINT_CONST(CLONE_NEWUSER);
    PRINT_CONST(CLONE_NEWNS);
    PRINT_CONST(MS_BIND);
    printf("  \"dummy\" : 0\n");
    printf("}\n");
}
"""


def get_constants():
  """
  Write out the source for, compile, and run a simple c-program that prints
  the value of needed glibc constants. Read the output of that program and
  store the value of constants in a Constants object. Return that object.
  """
  with tempfile.NamedTemporaryFile(mode='wb', prefix='print_constants',
                                   suffix='.cc', delete=False) as outfile:
    src_path = outfile.name
    outfile.write(GET_CONSTANTS_PROGRAM)

  with tempfile.NamedTemporaryFile(mode='wb', prefix='print_constants',
                                   suffix='.cc', delete=False) as binfile:
    bin_path = binfile.name

  try:
    os.remove(bin_path)
    subprocess.check_call(['gcc', '-o', bin_path, src_path])
    os.remove(src_path)

    constants_str = subprocess.check_output([bin_path])
    os.remove(bin_path)
    result = json.loads(constants_str)
    result.pop('dummy')

    return result
  except subprocess.CalledProcessError:
    logging.warn('Failed to compile/execute program to get glibc constants.'
                 ' Using baked-in values.')


def dump_constants(outfile):
  json.dump(get_constants(), outfile,
            sys.stdout, indent=2)
  outfile.write('\n')


def main():
  import argparse
  parser = argparse.ArgumentParser(description=__doc__)
  parser.parse_args()
  dump_constants(sys.stdout)


if __name__ == '__main__':
  main()
