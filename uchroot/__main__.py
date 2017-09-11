import argparse
import logging
import sys
import subprocess

import uchroot


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('-s', '--subprocess', action='store_true',
                      help='use subprocess instead of exec')

  log_levels = ['debug', 'info', 'warning', 'error']
  parser.add_argument('-l', '--log-level', default='info',
                      choices=log_levels,
                      help='Set the verbosity of messages')

  parser.add_argument('config_file', help='Path to config file')
  args = parser.parse_args()

  format_str = '%(levelname)-6s %(filename)s[%(lineno)-3s] : %(message)s'
  logging.basicConfig(level=getattr(logging, args.log_level.upper()),
                      format=format_str,
                      datefmt='%Y-%m-%d %H:%M:%S',
                      filemode='w')

  config = uchroot.parse_config(args.config_file)
  exec_spec = uchroot.ExecSpec(**config.pop('exec', {}))

  if args.subprocess:
    logging.info('Using subprocess call')
    return subprocess.call(exec_spec.argv, executable=exec_spec.path,
                           env=exec_spec.env,
                           preexec_fn=uchroot.Main(**config))
  else:
    # enter the jail
    uchroot.main(**config)

    # and start the requested program
    exec_spec()
    logging.error("Failed to start a shell")
    return 1

if __name__ == '__main__':
  sys.exit(main())
