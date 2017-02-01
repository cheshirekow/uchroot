"""Chroot without using linux user namespaces to circumvent the need for
   root priviledges.

   Base on: https://gist.github.com/cheshirekow/fe1451e245d1a0855ad3d1dca115aeca
"""

import argparse
import ctypes
import os
import json
import re
import subprocess
import sys

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


GET_CONSTANTS_PROGRAM = r"""
#include <sched.h>
#include <stdio.h>

#define PRINT_CONST(X) printf("  \"%s\" : %d,\n", #X, X)

int main(int argc, char** argv) {
    printf("{\n");
    PRINT_CONST(CLONE_NEWUSER);
    PRINT_CONST(CLONE_NEWNS);
    printf("  \"dummy\" : 0\n");
    printf("}\n");
}
"""

class Constants(object):
    def __init__(self):
        self.CLONE_NEWUSER = None
        self.CLONE_NEWNS = None


def get_constants() :
    # TODO(josh): tempfile
    src_path = '/tmp/print_constants.cc';
    bin_path = '/tmp/print_constants';

    with open(src_path, 'wb') as outfile:
        outfile.write(GET_CONSTANTS_PROGRAM)
    subprocess.check_call(['gcc', '-o', bin_path, src_path])
    constants_str = subprocess.check_output([bin_path])
    consts_json = json.loads(constants_str)

    consts_obj = Constants()
    for key, value in consts_json.iteritems():
        if key != 'dummy':
            setattr(consts_obj, key, value)

    return consts_obj


def get_glibc():
    """Return a ctypes wrapper around glibc."""

    glibc = ctypes.cdll.LoadLibrary('libc.so.6')

    # http://man7.org/linux/man-pages/man2/getuid.2.html
    glibc.getuid.restype = ctypes.c_uint # gid_t, uint32_t on my system
    glibc.getuid.argtypes = [] 

    # http://man7.org/linux/man-pages/man2/getgid.2.html
    glibc.getgid.restype = ctypes.c_uint # gid_t, uint32_t on my system
    glibc.getgid.argtypes = []

    # http://man7.org/linux/man-pages/man2/unshare.2.html
    glibc.unshare.restype = ctypes.c_int
    glibc.unshare.argtypes = [ctypes.c_int]

    # http://man7.org/linux/man-pages/man2/getpid.2.html
    glibc.getpid.restype = ctypes.c_int # pid_t, int32_t on my system
    glibc.getpid.argtypes = []

    # http://man7.org/linux/man-pages/man2/chroot.2.html
    glibc.chroot.restype = ctypes.c_int
    glibc.chroot.argtypes = [ctypes.c_char_p]

    # http://man7.org/linux/man-pages/man2/setresuid.2.html
    glibc.setresuid.restype = ctypes.c_int
    glibc.setresuid.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
    glibc.setresgid.restype = ctypes.c_int
    glibc.setresgid.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]

    return glibc


DEFAULT_BIN = '/bin/bash'
DEFAULT_ARGV = ['bash']
DEFAULT_PATH = ['/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', 
                '/sbin', '/bin']


class ExecSpec(object):
    def __init__(self, path, argv, env):
        self.path = path
        self.argv = argv
        self.env = env

    def __call__(self):
        os.execve(self.path, self.argv, self.env)


def parse_config(config_path):
    stripped_json_str = ''

    # NOTE(josh): strip comments out of the config file.
    with open(config_path, 'rb') as infile:
        for line in infile:
            line = re.sub('//.*$', '', line).rstrip()
            if line:
                stripped_json_str += line
                stripped_json_str += '\n'

    try:
        config_dict = json.loads(stripped_json_str)
    except (ValueError, KeyError):
        fmt_err('Failed to decode json:\n')
        sys.stderr.write(stripped_json_str)
        raise

    exec_dict = config_dict.pop('exec', {})
    exec_dict['path'] = exec_dict.pop('path', DEFAULT_BIN)
    exec_dict['argv'] = exec_dict.pop('argv', DEFAULT_ARGV)
    exec_env = exec_dict.pop('env', {})
    exec_path = exec_env.pop('path', DEFAULT_PATH)
    exec_env['PATH'] = ':'.join(exec_path)
    exec_dict['env'] = exec_env
    config_dict['exec_spec'] = ExecSpec(**exec_dict)
    return config_dict


def uchroot(rootfs=None, binds=None, qemu=None, emulate_root=False, 
            exec_spec=None):
    glibc = get_glibc()
    consts = get_constants()

    uid = glibc.getuid()
    gid = glibc.getgid()

    fmt_out("Before unshare, uid={}, gid={}\n", uid, gid).flush();

    # ---------------------------------------------------------------------
    #                     Create User Namespace
    # ---------------------------------------------------------------------

    # First, unshare the user namespace and assume admin capability in the
    # new namespace
    err = glibc.unshare(consts.CLONE_NEWUSER);
    if err != 0:
        fmt_err("Failed to unshare user namespace\n");
        sys.exit(1)
    
    # write a uid/pid map
    pid = glibc.getpid()
    fmt_out("My pid: {}\n", pid).flush()
    uid_map_path = fmt_str('/proc/{}/uid_map', pid)
    with open(uid_map_path, 'wb') as uid_map:
        fmt_out("Writing : {} (fd={})\n", uid_map_path, uid_map.fileno())
        fmt_file(uid_map, "{uid} {uid} 1\n", uid=uid)

    setgroups_path = fmt_str('/proc/{}/setgroups', pid)
    with open(setgroups_path, 'wb') as setgroups:
        fmt_out("Writing : {} (fd={})\n", setgroups_path, setgroups.fileno())
        fmt_file(setgroups, "deny\n")

    gid_map_path = fmt_str('/proc/{}/gid_map', pid)
    with open(gid_map_path, 'wb') as gid_map:
        fmt_out("Writing : {} (fd={})\n", gid_map_path, gid_map.fileno())
        fmt_file(gid_map, '{gid} {gid} 1\n', gid=gid)

    # ---------------------------------------------------------------------
    #                     Create Mount Namespace
    # ---------------------------------------------------------------------
    err = glibc.unshare(consts.CLONE_NEWNS)
    if err != 0:
        fmt_err('Failed to unshare mount namespace\n')

    # ---------------------------------------------------------------------
    #                             Chroot
    # ---------------------------------------------------------------------

    # Now chroot into the desired directory
    err = glibc.chroot(rootfs);
    if err != 0 :
        fmt_err("Failed to chroot\n");
        sys.exit(1)
    
    # Now drop admin in our namespace
    err = glibc.setresuid(uid, uid, uid);
    if err != 0:
        fmt_err("Failed to set uid\n");
    
    err = glibc.setresgid(gid, gid, gid);
    if(err) :
        printf("Failed to set gid\n");

    # and start the requested program
    exec_spec()
    fmt_err("Failed to start a shell")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config_file', help='Path to config file') 
    args = parser.parse_args()

    config = parse_config(args.config_file)
    uchroot(**config)


if __name__ == '__main__':
    main()