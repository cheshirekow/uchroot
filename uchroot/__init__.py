"""
Chroot without root using linux user namespaces to circumvent the need for
root priviledges.

Based on: https://gist.github.com/cheshirekow/fe1451e245d1a0855ad3d1dca115aeca
"""

# NOTE(josh): see http://man7.org/linux/man-pages/man5/subuid.5.html on
# subordinate UIDs.
# https://lwn.net/Articles/532593/

import ctypes
import errno
import logging
import os
import pwd
import json
import re
import subprocess
import sys
import tempfile

# A very simple c-program to print the value of certain glibc
# constants for the current system.
GET_CONSTANTS_PROGRAM = r"""
#include <sched.h>
#include <stdio.h>
#include <sys/mount.h>

#define PRINT_CONST(X) printf("  \"%s\" : %d,\n", #X, X)

int main(int argc, char** argv) {
    printf("{\n");
    [replaceme]
    printf("  \"dummy\" : 0\n");
    printf("}\n");
}
"""


class Constants(object):
  """A collection of glibc constants."""

  def __init__(self):
    # pylint: disable=invalid-name
    self.CLONE_NEWUSER = 0x10000000
    self.CLONE_NEWNS = 0x20000
    self.MS_BIND = 0x1000


def get_constants():
  """
  Write out the source for, compile, and run a simple c-program that prints
  the value of needed glibc constants. Read the output of that program and
  store the value of constants in a Constants object. Return that object.
  """

  consts_obj = Constants()
  stmts = ['PRINT_CONST({});'.format(name) for name in dir(consts_obj)
           if not name.startswith('_')]
  replacement = '\n    '.join(stmts)
  program_source = GET_CONSTANTS_PROGRAM.replace("[replaceme]", replacement)

  with tempfile.NamedTemporaryFile(mode='wb', prefix='print_constants',
                                   suffix='.cc', delete=False) as outfile:
    src_path = outfile.name
    outfile.write(program_source)

  with tempfile.NamedTemporaryFile(mode='wb', prefix='print_constants',
                                   suffix='.cc', delete=False) as binfile:
    bin_path = binfile.name

  try:
    os.remove(bin_path)
    subprocess.check_call(['gcc', '-o', bin_path, src_path])
    os.remove(src_path)

    constants_str = subprocess.check_output([bin_path])
    os.remove(bin_path)
    consts_json = json.loads(constants_str)

    for key, value in consts_json.iteritems():
      if key != 'dummy':
        setattr(consts_obj, key, value)
  except subprocess.CalledProcessError:
    logging.warn('Failed to compile/execute program to get glibc constants.'
                 ' Using baked-in values.')

  return consts_obj


def get_glibc():
  """
  Return a ctypes wrapper around glibc. Only wraps functions needed by this
  script.
  """

  glibc = ctypes.CDLL('libc.so.6', use_errno=True)

  # http://man7.org/linux/man-pages/man2/getuid.2.html
  glibc.getuid.restype = ctypes.c_uint  # gid_t, uint32_t on my system
  glibc.getuid.argtypes = []

  # http://man7.org/linux/man-pages/man2/getgid.2.html
  glibc.getgid.restype = ctypes.c_uint  # gid_t, uint32_t on my system
  glibc.getgid.argtypes = []

  # http://man7.org/linux/man-pages/man2/unshare.2.html
  glibc.unshare.restype = ctypes.c_int
  glibc.unshare.argtypes = [ctypes.c_int]

  # http://man7.org/linux/man-pages/man2/getpid.2.html
  glibc.getpid.restype = ctypes.c_int  # pid_t, int32_t on my system
  glibc.getpid.argtypes = []

  # http://man7.org/linux/man-pages/man2/chroot.2.html
  glibc.chroot.restype = ctypes.c_int
  glibc.chroot.argtypes = [ctypes.c_char_p]

  # http://man7.org/linux/man-pages/man2/setresuid.2.html
  glibc.setresuid.restype = ctypes.c_int
  glibc.setresuid.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
  glibc.setresgid.restype = ctypes.c_int
  glibc.setresgid.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]

  # http://man7.org/linux/man-pages/man2/mount.2.html
  glibc.mount.restype = ctypes.c_int
  glibc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                          ctypes.c_uint,  # unsigned long
                          ctypes.c_void_p]

  return glibc


def get_subid_range(subid_path, uid):
  """Return the subordinate user/group id and count for the given user."""

  username = username = pwd.getpwuid(uid)[0]
  with open(subid_path, 'r') as subuid:
    for line in subuid:
      subuid_name, subuid_min, subuid_count = line.strip().split(':')
      if subuid_name == username:
        return (int(subuid_min), int(subuid_count))
      else:
        try:
          subuid_uid = int(subuid_name)
          if subuid_uid == uid:
            return (int(subuid_min), int(subuid_count))
        except ValueError:
          pass

  raise ValueError("user {}({}) not found in subid file {}".format(
      username, uid, subid_path))


def write_id_map(id_map_path, id_outside, subid_range):
  """
  Write uid_map or gid_map.
  NOTE(josh): doesn't work. We need CAP_SETUID (CAP_SETGID) in the *parent*
  namespace to be allowed to do this. Evidently, that is why there the
  setuid-root newuidmap/newgidmap programs exist.
  """
  with open(id_map_path, 'wb') as id_map:
    logging.debug("Writing : %s (fd=%d)\n", id_map_path, id_map.fileno())
    id_map.write("{id_inside} {id_outside} {count}\n".format(
        id_inside=0, id_outside=id_outside, count=1))
    id_map.write("{id_inside} {id_outside} {count}\n".format(
        id_inside=1, id_outside=subid_range[0], count=subid_range[1]))


def write_setgroups(pid):
  setgroups_path = '/proc/{}/setgroups'.format(pid)
  with open(setgroups_path, 'wb') as setgroups:
    logging.debug("Writing : %s (fd=%d)\n", setgroups_path, setgroups.fileno())
    setgroups.write("deny\n")


def set_id_map(idmap_bin, pid, id_outside, subid_range):
  """Set uid_map or gid_map through subprocess calls."""
  logging.debug("Calling %s\n", idmap_bin)
  subprocess.check_call(['/usr/bin/{}'.format(idmap_bin), str(pid),
                         '0', str(id_outside), '1',
                         '1', str(subid_range[0]), str(subid_range[1])])


def make_sure_is_dir(need_dir, source):
  """
  Ensure that the given path is a directory, removing a regular file if
  there is one at that location, creating the directory and all its
  parents if needed.
  """

  if not os.path.isdir(need_dir):
    if os.path.exists(need_dir):
      logging.warn("removing rootfs bind target %s because it"
                   " is not a directory\n", need_dir)
      os.remove(need_dir)
    logging.warn("creating rootfs directory %s because it is "
                 " needed to bind mount %s.\n", need_dir, source)
    os.makedirs(need_dir)


def make_sure_is_file(need_path, source):
  """
  Ensure that the parent directory of need_path exists, and that there is
  a regular file at that location, creating them if needed.
  """
  make_sure_is_dir(os.path.dirname(need_path), source)

  if not os.path.exists(need_path):
    logging.warn("creating rootfs regular file %s because it "
                 " is a requested mount-point for %s\n", need_path, source)
    with open(need_path, 'wb') as touchfile:
      touchfile.write('# written by uchroot')


def enter(read_fd, write_fd, rootfs=None, binds=None, qemu=None, identity=None,
          cwd=None):
  """
  Chroot into rootfs with a new user and mount namespace, then execute
  the desired command.
  """
  # pylint: disable=too-many-locals,too-many-statements

  if not binds:
    binds = []
  if not identity:
    identity = [0, 0]
  if not cwd:
    cwd = '/'

  glibc = get_glibc()
  consts = get_constants()

  uid = glibc.getuid()
  gid = glibc.getgid()

  logging.debug("Before unshare, uid=%d, gid=%d\n", uid, gid)
  # ---------------------------------------------------------------------
  #                     Create User Namespace
  # ---------------------------------------------------------------------

  # First, unshare the user namespace and assume admin capability in the
  # new namespace
  err = glibc.unshare(consts.CLONE_NEWUSER)
  if err != 0:
    raise OSError(err, "Failed to unshared user namespace", None)

  # write a uid/pid map
  pid = glibc.getpid()
  logging.debug("My pid: %d\n", pid)

  # Notify the helper that we have created the new namespace, and we need
  # it to set our uid/gid map
  logging.debug("Waiting for helper to set my uid/gid map")
  os.write(write_fd, "#")

  # Wait for the helper to finish setting our uid/gid map
  os.read(read_fd, 1)
  logging.debug("Helper has finished setting my uid/gid map")

  # ---------------------------------------------------------------------
  #                     Create Mount Namespace
  # ---------------------------------------------------------------------
  err = glibc.unshare(consts.CLONE_NEWNS)
  if err != 0:
    logging.error('Failed to unshare mount namespace')

  null_ptr = ctypes.POINTER(ctypes.c_char)()
  for bind_spec in binds:
    if ':' in bind_spec:
      source, dest = bind_spec.split(':')
    else:
      source = bind_spec
      dest = bind_spec

    dest = dest.lstrip('/')
    rootfs_dest = os.path.join(rootfs, dest)
    logging.debug('Binding: %s -> %s', source, rootfs_dest)
    assert os.path.exists(source),\
        "source directory to bind does not exit {}".format(source)

    # Create the mountpoint if it is not already in the rootfs
    if os.path.isdir(source):
      make_sure_is_dir(rootfs_dest, source)
    else:
      make_sure_is_file(rootfs_dest, source)

    result = glibc.mount(source, rootfs_dest, null_ptr, consts.MS_BIND,
                         null_ptr)
    if result == -1:
      err = ctypes.get_errno()
      logging.warn('[%s](%d) %s', errno.errorcode.get(err, '??'), err,
                   os.strerror(err))

  if qemu:
    dest = qemu.lstrip('/')
    rootfs_dest = os.path.join(rootfs, dest)
    make_sure_is_dir(os.path.dirname(rootfs_dest), qemu)
    logging.debug("Installing %s", qemu)
    with open(rootfs_dest, 'wb') as outfile:
      with open(qemu, 'rb') as infile:
        chunk = infile.read(1024 * 4)
        while chunk:
          outfile.write(chunk)
          chunk = infile.read(1024 * 4)

    os.chmod(rootfs_dest, 0o755)

  # ---------------------------------------------------------------------
  #                             Chroot
  # ---------------------------------------------------------------------

  # Now chroot into the desired directory
  err = glibc.chroot(rootfs)
  if err != 0:
    logging.error("Failed to chroot")
    raise OSError(err, "Failed to chroot", rootfs)


  # Set the cwd
  os.chdir(cwd)

  # Now drop admin in our namespace
  err = glibc.setresuid(identity[0], identity[0], identity[0])
  if err != 0:
    logging.error("Failed to set uid")

  err = glibc.setresgid(identity[1], identity[1], identity[1])
  if err:
    logging.error("Failed to set gid\n")


def validate_id_range(requested_range, allowed_range):
  """Check that the requested id range lies within the users allowed id
     range."""
  assert (requested_range[0] > 0) and (requested_range[1] > 0), \
      "id maps must satisfy min ({}) > 0 and count ({}) > 0".format(
          requested_range[0], requested_range[1])

  min_requested = requested_range[0]
  max_requested = min_requested + requested_range[1]
  min_allowed = allowed_range[0]
  max_allowed = min_allowed + allowed_range[1]

  assert (min_requested >= min_allowed and max_requested <= max_allowed), \
      "id range ({}, {}) is not contained your allowed range ({}, {})".format(
          requested_range[0], requested_range[1], allowed_range[0],
          allowed_range[1])


def set_userns_idmap(chroot_pid, uid_range, gid_range):
  """Writes uid/gid maps for the chroot process."""
  uid = os.getuid()
  gid = os.getgid()

  subuid_range = get_subid_range('/etc/subuid', uid)
  if uid_range:
    validate_id_range(uid_range, subuid_range)
  else:
    uid_range = subuid_range

  subgid_range = get_subid_range('/etc/subgid', uid)
  if gid_range:
    validate_id_range(gid_range, subgid_range)
  else:
    gid_range = subgid_range

  set_id_map('newuidmap', chroot_pid, uid, uid_range)
  write_setgroups(chroot_pid)
  set_id_map('newgidmap', chroot_pid, gid, gid_range)


def main(rootfs, binds=None, qemu=None, identity=None, uid_range=None,
         gid_range=None, cwd=None):
  """Fork off a helper subprocess, enter the chroot jail. Wait for the helper
     to  call the setuid-root helper programs and configure the uid map of the
     jail, then return."""

  # Pipes used to synchronize between the helper process and the chroot
  # process. Could also use eventfd, but this is simpler because python
  # already has os.pipe()
  helper_read_fd, primary_write_fd = os.pipe()
  primary_read_fd, helper_write_fd = os.pipe()

  parent_pid = os.getpid()
  child_pid = os.fork()

  if child_pid == 0:
    # Wait for the primary to create its new namespace
    os.read(helper_read_fd, 1)

    # Set the uid/gid map using the setuid helper programs
    set_userns_idmap(parent_pid, uid_range, gid_range)
    # Inform the primary that we have finished setting its uid/gid map.
    os.write(helper_write_fd, '#')

    # NOTE(josh): using sys.exit() will interfere with the interpreter in the
    # parent process.
    # see: https://docs.python.org/3/library/os.html#os._exit
    os._exit(0)  # pylint: disable=protected-access
  else:
    enter(primary_read_fd, primary_write_fd, rootfs, binds, qemu,
          identity, cwd)


def process_environment(env_dict):
  """Given an environment dictionary, merge any lists with pathsep and return
     the new dictionary."""
  out_dict = {}
  for key, value in env_dict.iteritems():
    if isinstance(value, list):
      out_dict[key] = ':'.join(value)
    elif isinstance(value, str) or isinstance(value, unicode):
      out_dict[key] = value
    else:
      out_dict[key] = str(value)
  return out_dict


# exec defaults
DEFAULT_BIN = '/bin/bash'
DEFAULT_ARGV = ['bash']
DEFAULT_PATH = ['/usr/sbin', '/usr/bin', '/sbin', '/bin']


class ExecSpec(object):
  """Simple object to hold together the path, argument vector, and environment
     of an exec call."""

  def __init__(self, path=None, argv=None, env=None):
    if path:
      self.path = path
      if not argv:
        argv = [path.split('/')[-1]]
    else:
      self.path = DEFAULT_BIN

    if argv:
      self.argv = argv
    else:
      self.argv = DEFAULT_ARGV

    if env:
      self.env = process_environment(env)
    else:
      self.env = process_environment(dict(PATH=DEFAULT_PATH))

  def __call__(self):
    os.execve(self.path, self.argv, self.env)


class Main(object):
  """Simple bind for subprocess prexec_fn."""

  def __init__(self, *args, **kwargs):
    self.args = args
    self.kwargs = kwargs

  def __call__(self):
    main(*self.args, **self.kwargs)

def parse_config(config_path):
  """
  Open the config file as json, strip comments, load it and return the
  resulting dictionary.
  """

  stripped_json_str = ''

  # NOTE(josh): strip comments out of the config file.
  with open(config_path, 'rb') as infile:
    for line in infile:
      line = re.sub('//.*$', '', line).rstrip()
      if line:
        stripped_json_str += line
        stripped_json_str += '\n'

  try:
    return json.loads(stripped_json_str)
  except (ValueError, KeyError):
    logging.error('Failed to decode json:\n%s', stripped_json_str)
    raise
