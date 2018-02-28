
# The directory to chroot into
rootfs = "/tmp/trusty_arm64"

# List of paths to bind into the new root directory. These binds are
# done inside a mount namespace and will not be reflected outside
# the process tree started by the script.
binds = [
    # "/dev/pts",
    "/dev/urandom",
    # "/etc/group",
    # "/etc/passwd",
    "/etc/resolv.conf",
]

# If specified, indicates the path to a qemu instance that should be bound
# into the mount namespace of the jail
qemu = "/usr/bin/qemu-aarch64-static"

# After entering the jail, assume this [uid, gid]. [0, 0] for root.
identity = (0, 0)

# uids in the namespace starting at 1 are mapped to uids outside the
# namespace starting with this value and up to this many ids. Note that
# the uid range outside the namespace must lie within the current users
# allowed subordinate uids. See (or modify) /etc/subid for the range
# available to your user.
uid_range = (100000, 65536)

# Aame as uid_map above, but for gids.
gid_range = (100000, 65536)

# Set the current working directory to this inside the jail
cwd = "/"

# The following variables specify what to execute after chrooting into the jail

# The path of the program to execute
exbin = "/bin/bash"

# The argument vector to expose as argv,argc to the called process
argv = ["bash"],

# The environment of the called process. Use an empty dictionary for an
# empty environment, or None to use the host environment.
env = {
    # Any environment variable encountered as a list will be join()ed using
    # path separator (':')
    "PATH": [
        # "/usr/local/sbin",
        # "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin"
    ],
    "DEBIAN_FRONTEND": "noninteractive",
    "DEBCONF_NONINTERACTIVE_SEEN": "true",
    "LC_ALL": "C",
    "LANGUAGE": "C",
    "LANG": "C"
}
