"""
Chroot without root priviledges

This is a pretty simple process spawner that automates the construction of
user and mount namespaces in order to create chroot jails without root. It's not
entirely a no-root solution because it requires the newuidmap and newgidmap
set-uid-root helper functions (on ubuntu, installed with the uidmap package).
This requirement is not necessary if you only need to enter the chroot
jail with a single user id mapped.
"""

import argparse
import io
import logging
import sys

import uchroot


def parse_bool(string):
  if string.lower() in ('y', 'yes', 't', 'true', '1', 'yup', 'yeah', 'yada'):
    return True
  elif string.lower() in ('n', 'no', 'f', 'false', '0', 'nope', 'nah', 'nada'):
    return False

  logging.warn("Ambiguous truthiness of string '%s' evalutes to 'FALSE'",
               string)
  return False


def main():
  format_str = '%(levelname)-4s %(filename)s[%(lineno)-3s] : %(message)s'
  logging.basicConfig(level=logging.INFO,
                      format=format_str,
                      datefmt='%Y-%m-%d %H:%M:%S',
                      filemode='w')

  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('-v', '--version', action='version',
                      version=uchroot.VERSION)
  parser.add_argument('-l', '--log-level', default='info',
                      choices=['debug', 'info', 'warning', 'error'],
                      help='Set the verbosity of messages')
  parser.add_argument('-s', '--subprocess', action='store_true',
                      help='use subprocess instead of exec')
  parser.add_argument('-c', '--config', help='Path to config file')
  parser.add_argument('--dump-config', action='store_true',
                      help='Dump default config and exit')

  config = uchroot.Main().as_dict()
  config.update(uchroot.Exec().as_dict())

  for key, value in config.items():
    helpstr = uchroot.VARDOCS.get(key, None)
    if key == 'rootfs':
      continue
    # NOTE(josh): argparse store_true isn't what we want here because we want
    # to distinguish between "not specified" = "default" and "specified"
    elif isinstance(value, bool):
      parser.add_argument('--' + key.replace('_', '-'), nargs='?', default=None,
                          const=True, type=parse_bool, help=helpstr)
    elif isinstance(value, (str, unicode, int, float)) or value is None:
      parser.add_argument('--' + key.replace('_', '-'))
    # NOTE(josh): argparse behavior is that if the flag is not specified on
    # the command line the value will be None, whereas if it's specified with
    # no arguments then the value will be an empty list. This exactly what we
    # want since we can ignore `None` values.
    elif isinstance(value, (list, tuple)):
      if value:
        argtype = type(value[0])
      else:
        argtype = None
      parser.add_argument('--' + key.replace('_', '-'), nargs='*',
                          type=argtype, help=helpstr)

  parser.add_argument('rootfs', nargs='?',
                      help='path of the rootfs to enter')
  args = parser.parse_args()

  if args.dump_config:
    uchroot.dump_config(sys.stdout)
    sys.exit(0)

  logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))

  if args.config:
    with io.open(args.config, encoding='utf8') as infile:
      # pylint: disable=W0122
      exec(infile.read(), config)

  for key, value in vars(args).items():
    if value is not None and key in config:
      config[key] = value

  knownkeys = uchroot.Main.get_field_names() + uchroot.Exec.get_field_names()
  unknownkeys = []
  for key in config:
    if key.startswith('_'):
      continue

    if key in knownkeys:
      continue

    unknownkeys.append(key)

  if unknownkeys:
    logging.warn("Unrecognized config variables: %s", ", ".join(unknownkeys))

  mainobj = uchroot.Main(**config)
  execobj = uchroot.Exec(**config)

  if args.subprocess:
    execobj.subprocess(preexec_fn=mainobj)
  else:
    # enter the jail
    mainobj()
    # and start the requested program
    execobj()
    logging.error("Failed to start a shell")
    return 1


if __name__ == '__main__':
  sys.exit(main())
