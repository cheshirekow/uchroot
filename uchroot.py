"""Chroot without root using linux user namespaces to circumvent the need for
   root priviledges.

   Base on: https://gist.github.com/cheshirekow/fe1451e245d1a0855ad3d1dca115aeca
"""

# NOTE(josh): see http://man7.org/linux/man-pages/man5/subuid.5.html on
# subordinate UIDs.
# https://lwn.net/Articles/532593/

import argparse
import ctypes
import errno
import os
import pwd
import json
import re
import subprocess
import sys
import tempfile


class Path(str):
    "A class to make it easier to create paths"

    def __call__(self, *args):
        return Path(os.path.join(self, *args))


class FmtWrapper(object):
    """Wrap a file-like object with a callable taking format strings and
       args that will write() the formatted string to the file-like object.
    """

    def __init__(self, fileobj):
        self.fileobj = fileobj

    def __call__(self, fmt, *args, **kwargs):
        self.fileobj.write(fmt.format(*args, **kwargs))
        return self

    def flush(self):
        self.fileobj.flush()
        return self


def fmt_str(fmt, *args, **kwargs):
    return fmt.format(*args, **kwargs)


def fmt_out(fmt, *args, **kwargs):
    return FmtWrapper(sys.stdout)(fmt, *args, **kwargs)


def fmt_err(fmt, *args, **kwargs):
    return FmtWrapper(sys.stderr)(fmt, *args, **kwargs)


def fmt_file(fileobj, fmt, *args, **kwargs):
    return FmtWrapper(fileobj)(fmt, *args, **kwargs)


def fmt_raise(ex_class, fmt, *args, **kwargs):
    raise ex_class(fmt.format(*args, **kwargs))


def fmt_assert(assertion, fmt, *args, **kwargs):
    assert assertion, fmt.format(*args, **kwargs)


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
        self.CLONE_NEWUSER = None
        self.CLONE_NEWNS = None
        self.MS_BIND = None


def get_constants():
    """Write out the source for, compile, and run a simple c-program that prints
       the value of needed glibc constatns. Read the output of that program and
       store the value of constants in a Constants object. Return that object.
    """

    consts_obj = Constants()
    stmts = [fmt_str('PRINT_CONST({});', name) for name in dir(consts_obj)
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

    os.remove(bin_path)
    subprocess.check_call(['gcc', '-o', bin_path, src_path])
    os.remove(src_path)

    constants_str = subprocess.check_output([bin_path])
    os.remove(bin_path)
    consts_json = json.loads(constants_str)

    for key, value in consts_json.iteritems():
        if key != 'dummy':
            setattr(consts_obj, key, value)

    return consts_obj


def get_glibc():
    """Return a ctypes wrapper around glibc. Only wraps functions needed by
       this script."""

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


class ExecSpec(object):
    """Simple object to hold together the path, argument vector, and environment
       of an exec call."""

    def __init__(self, path, argv, env):
        self.path = path
        self.argv = argv
        self.env = env

    def __call__(self):
        os.execve(self.path, self.argv, self.env)


def parse_config(config_path):
    """Open the config file as json, strip comments, load it and return the
       resulting dictionary."""

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
        fmt_err('Failed to decode json:\n')
        sys.stderr.write(stripped_json_str)
        raise


# Config defaults
DEFAULT_BIN = '/bin/bash'
DEFAULT_ARGV = ['bash']
DEFAULT_PATH = ['/usr/sbin', '/usr/bin', '/sbin', '/bin']


def process_config(config_dict):
    """Process a config dictionary replacing missing values with defaults,
       joining path components, etc."""

    # Set default identity to root if not specific in config
    config_dict['identity'] = config_dict.pop('identity', [0, 0])

    # Set default working directory if not specified in config
    config_dict['cwd'] = config_dict.pop('cwd', '/')

    # Set default command binary, argument vector, and environment if not
    # specified in config
    exec_dict = config_dict.pop('exec', {})
    exec_dict['path'] = exec_dict.pop('path', DEFAULT_BIN)
    exec_dict['argv'] = exec_dict.pop('argv', DEFAULT_ARGV)
    exec_env = exec_dict.pop('env', {})
    exec_path = exec_env.pop('path', DEFAULT_PATH)

    # Compose the path environment variable with a string join
    exec_env['PATH'] = ':'.join(exec_path)
    exec_dict['env'] = exec_env

    # Replace the desired command dictionary with an object for convenience
    config_dict['exec_spec'] = ExecSpec(**exec_dict)
    return config_dict


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

    raise fmt_raise(ValueError, "user {}({}) not found in subid file {}",
                    username, uid, subid_path)


def write_id_map(id_map_path, id_outside, subid_range):
    """Write uid_map or gid_map.
       NOTE(josh): doesn't work. We need CAP_SETUID (CAP_SETGID) in the *parent*
       namespace to be allowed to do this. Evidently, that is why there the
       setuid-root newuidmap/newgidmap programs exist.
    """
    with open(id_map_path, 'wb') as id_map:
        fmt_out("Writing : {} (fd={})\n", id_map_path, id_map.fileno())
        fmt_file(id_map, "{id_inside} {id_outside} {count}\n",
                 id_inside=0,
                 id_outside=id_outside,
                 count=1)
        fmt_file(id_map, "{id_inside} {id_outside} {count}\n",
                 id_inside=1,
                 id_outside=subid_range[0],
                 count=subid_range[1])


def write_setgroups(pid):
    setgroups_path = fmt_str('/proc/{}/setgroups', pid)
    with open(setgroups_path, 'wb') as setgroups:
        fmt_out("Writing : {} (fd={})\n", setgroups_path, setgroups.fileno())
        fmt_file(setgroups, "deny\n")


def set_id_map(idmap_bin, pid, id_outside, subid_range):
    """Set uid_map or gid_map through subprocess calls."""
    fmt_out("Calling {}\n", idmap_bin)
    subprocess.check_call([fmt_str('/usr/bin/{}', idmap_bin), str(pid),
                           '0', str(id_outside), '1',
                           '1', str(subid_range[0]), str(subid_range[1])])


def make_sure_is_dir(need_dir, source):
    """Ensure that the given path is a directory, removing a regular file if
       there is one at that location, creating the directory and all its
       parents if needed.
    """

    if not os.path.isdir(need_dir):
        if os.path.exists(need_dir):
            fmt_err("WARNING: removing rootfs bind target {} because it"
                    " is not a directory\n", need_dir)
            os.remove(need_dir)
        fmt_err("WARNING: creating rootfs directory {} because it is "
                " needed to bind mount.\n", need_dir, source)
        os.makedirs(need_dir)


def make_sure_is_file(need_path, source):
    """Ensure that the parent directory of need_path exists, and that there is
       a regular file at that location, creating them if needed."""
    make_sure_is_dir(os.path.dirname(need_path), source)

    if not os.path.exists(need_path):
        fmt_err("WARNING: creating rootfs regular file {} because it "
                " is a requested mount-point for {}\n", need_path, source)
        with open(need_path, 'wb') as touchfile:
            touchfile.write('# written by uchroot.py')


def uchroot(read_fd, write_fd, rootfs=None, binds=None,
            qemu=None, identity=None, cwd=None, exec_spec=None):
    """Chroot into rootfs with a new user and mount namespace, then execute
       the desired command."""
    # pylint: disable=too-many-locals,too-many-statements

    rootfs = Path(rootfs)

    glibc = get_glibc()
    consts = get_constants()

    uid = glibc.getuid()
    gid = glibc.getgid()

    fmt_out("Before unshare, uid={}, gid={}\n", uid, gid).flush()
    # ---------------------------------------------------------------------
    #                     Create User Namespace
    # ---------------------------------------------------------------------

    # First, unshare the user namespace and assume admin capability in the
    # new namespace
    err = glibc.unshare(consts.CLONE_NEWUSER)
    if err != 0:
        fmt_err("Failed to unshare user namespace\n")
        sys.exit(1)

    # write a uid/pid map
    pid = glibc.getpid()
    fmt_out("My pid: {}\n", pid).flush()

    # Notify the helper that we have created the new namespace, and we need
    # it to set our uid/gid map
    fmt_out("Waiting for helper to set my uid/gid map\n").flush()
    os.write(write_fd, "#")

    # Wait for the helper to finish setting our uid/gid map
    os.read(read_fd, 1)
    fmt_out("Helper has finished setting my uid/gid map\n").flush()

    # ---------------------------------------------------------------------
    #                     Create Mount Namespace
    # ---------------------------------------------------------------------
    err = glibc.unshare(consts.CLONE_NEWNS)
    if err != 0:
        fmt_err('Failed to unshare mount namespace\n')

    null_ptr = ctypes.POINTER(ctypes.c_char)()
    for bind_spec in binds:
        if ':' in bind_spec:
            source, dest = bind_spec.split(':')
        else:
            source = bind_spec
            dest = bind_spec

        dest = dest.lstrip('/')
        fmt_out('Binding: {} -> {} ', source, rootfs(dest))
        fmt_assert(os.path.exists(source),
                   "source directory to bind does not exit {}", source)

        # Create the mountpoint if it is not already in the rootfs
        if os.path.isdir(source):
            make_sure_is_dir(rootfs(dest), source)
        else:
            make_sure_is_file(rootfs(dest), source)

        result = glibc.mount(source, rootfs(dest), null_ptr, consts.MS_BIND,
                             null_ptr)
        if result == -1:
            err = ctypes.get_errno()
            fmt_out('\n').flush()
            fmt_err('  [{}]({}) {}\n', errno.errorcode.get(err, '??'), err,
                    os.strerror(err))
        else:
            fmt_out('OK\n')

    if qemu:
        dest = qemu.lstrip('/')
        make_sure_is_dir(os.path.dirname(rootfs(dest)), qemu)
        with open(rootfs(dest), 'wb') as outfile:
            with open(qemu, 'rb') as infile:
                for chunk in infile.read(1024 * 4):
                    outfile.write(chunk)

    # ---------------------------------------------------------------------
    #                             Chroot
    # ---------------------------------------------------------------------

    # Now chroot into the desired directory
    err = glibc.chroot(rootfs)
    if err != 0:
        fmt_err("Failed to chroot\n")
        sys.exit(1)

    # Set the cwd
    os.chdir(cwd)

    # Now drop admin in our namespace
    err = glibc.setresuid(identity[0], identity[0], identity[0])
    if err != 0:
        fmt_err("Failed to set uid\n")

    err = glibc.setresgid(identity[1], identity[1], identity[1])
    if err:
        fmt_err("Failed to set gid\n")

    # and start the requested program
    exec_spec()
    fmt_err("Failed to start a shell")
    sys.exit(1)


def validate_id_range(requested_range, allowed_range):
    """Check that the requested id range lies within the users allowed id
       range."""
    fmt_assert((requested_range[0] > 0) and (requested_range[1] > 0),
               "id maps must satisfy min ({}) > 0 and count ({}) > 0",
               requested_range[0], requested_range[1])

    min_requested = requested_range[0]
    max_requested = min_requested + requested_range[1]
    min_allowed = allowed_range[0]
    max_allowed = min_allowed + allowed_range[1]

    fmt_assert(min_requested >= min_allowed,
               max_requested <= max_allowed,
               "id range ({}, {}) is not contained your allowed range ({}, {})",
               requested_range[0], requested_range[1],
               allowed_range[0], allowed_range[1])


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


def uchroot_main(config):
    """Fork off a subprocess to enter the chroot jail. Wait for it to enter
       it's user namespace, and then call the setuid-root helper programs to
       configure it's uid map."""

    # Pipes used to synchronize between the helper process and the chroot
    # process. Could also use eventfd, but this is simpler because python
    # already has os.pipe()
    helper_read_fd, primary_write_fd = os.pipe()
    primary_read_fd, helper_write_fd = os.pipe()

    uid_range = config.pop('uid_range')
    gid_range = config.pop('gid_range')

    parent_pid = os.getpid()
    child_pid = os.fork()

    if child_pid == 0:
        # Wait for the primary to create its new namespace
        os.read(helper_read_fd, 1)

        # Set the uid/gid map using the setuid helper programs
        set_userns_idmap(parent_pid, uid_range, gid_range)
        # Inform the primary that we have finished setting its uid/gid map.
        os.write(helper_write_fd, '#')
    else:
        config = process_config(config)
        uchroot(primary_read_fd, primary_write_fd, **config)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config_file', help='Path to config file')
    args = parser.parse_args()
    config = parse_config(args.config_file)
    uchroot_main(config)


if __name__ == '__main__':
    sys.exit(main())
