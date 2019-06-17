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
#include <signal.h>
#include <stdio.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/signalfd.h>

#define PRINT_CONST(X) printf("  \"%s\" : \"0x%x\",\n", #X, X)




int main(int argc, char** argv) {
    printf("{\n");
    PRINT_CONST(CLONE_NEWUSER);
    PRINT_CONST(CLONE_NEWNS);
    PRINT_CONST(IN_NONBLOCK);
    PRINT_CONST(IN_CLOEXEC);

    PRINT_CONST(IN_ACCESS);
    PRINT_CONST(IN_ATTRIB);
    PRINT_CONST(IN_CLOSE_WRITE);
    PRINT_CONST(IN_CLOSE_NOWRITE  );
    PRINT_CONST(IN_CREATE);
    PRINT_CONST(IN_DELETE);
    PRINT_CONST(IN_DELETE_SELF);
    PRINT_CONST(IN_MODIFY);
    PRINT_CONST(IN_MOVE_SELF);
    PRINT_CONST(IN_MOVED_FROM);
    PRINT_CONST(IN_MOVED_TO);
    PRINT_CONST(IN_OPEN);

    PRINT_CONST(MS_BIND);
    PRINT_CONST(MS_REC);

    PRINT_CONST(SFD_NONBLOCK);
    PRINT_CONST(SFD_CLOEXEC);

    PRINT_CONST(SIG_BLOCK);
    PRINT_CONST(SIG_UNBLOCK);
    PRINT_CONST(SIG_SETMASK);

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
    logging.warning('Failed to compile/execute program to get glibc constants.'
                    ' Using baked-in values.')


def dump_constants(outfile, which_format):
  constants = get_constants()
  if which_format == "json":
    json.dump(constants, outfile,
              indent=2, sort_keys=True)
  elif which_format == "glibc":
    for key, value in sorted(constants.items()):
      sys.stdout.write("glibc.{} = {}\n".format(key, value))
  else:
    for key, value in sorted(constants.items()):
      sys.stdout.write("{} = {}\n".format(key, value))

  outfile.write('\n')


def main():
  import argparse
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("-f", "--format", choices=["glibc", "python", "json"],
                      default="python")
  args = parser.parse_args()
  dump_constants(sys.stdout, args.format)


if __name__ == '__main__':
  main()
