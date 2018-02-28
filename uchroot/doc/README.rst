=======
uchroot
=======

Chroot without root priviledges.

``uchroot.py`` uses linux user namespaces and mount namespaces to create
chroot jails without root. It's not entirely a no-root solution because it
requires the newuidmap and newgidmap set-uid-root helper functions (on ubuntu,
installed with the uidmap package).

This requirement is not really necessary if you only need to enter the chroot
jail with a single user id mapped.

------------
Requirements
------------

Requires a linux built with user namespaces enabled (note that red hat does
not by default) and the ``newuidmap`` setuid helper programs (install the
``newuidmap`` ubuntu package).

To check if your kernel is built with user namespaces, on ubuntu::

  ~$ cat /boot/config-`uname -r` | grep CONFIG_USER_NS
  CONFIG_USER_NS=y

On other linuxes, perhaps try::

  ~$ zcat /proc/config.gz | grep CONFIG_USER_NS

-----
Usage
-----

::

    usage: uchroot [-h] [-v] [-l {debug,info,warning,error}] [-s] [-c CONFIG]
                    [rootfs]

    Chroot without root priviledges This is a pretty simple process spawner that
    automates the construction of user and mount namespaces in order to create
    chroot jails without root. It's not entirely a no-root solution because it
    requires the newuidmap and newgidmap set-uid-root helper functions (on ubuntu,
    installed with the uidmap package). This requirement is not necessary if you
    only need to enter the chroot jail with a single user id mapped.

    positional arguments:
    rootfs                path of the rootfs to enter

    optional arguments:
    -h, --help            show this help message and exit
    -v, --version         show program's version number and exit
    -l {debug,info,warning,error}, --log-level {debug,info,warning,error}
                            Set the verbosity of messages
    -s, --subprocess      use subprocess instead of exec
    -c CONFIG, --config CONFIG
                            Path to config file
    --argv [ARGV [ARGV ...]]
    --cwd CWD
    --binds [BINDS [BINDS ...]]
    --gid-range [GID_RANGE [GID_RANGE ...]]
    --exbin EXBIN
    --qemu QEMU
    --uid-range [UID_RANGE [UID_RANGE ...]]
    --identity [IDENTITY [IDENTITY ...]]

Advanced configurations can be specified with a configuration file in python
format. Command line arguments override options specified in a configuration
file::

    # The directory to chroot into
    rootfs = "/tmp/rootfs"

    # List of paths to bind into the new root directory. These binds are
    # done inside a mount namespace and will not be reflected outside
    # the process tree started by the script.
    binds = [
        "/dev/urandom",
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

    # Same as uid_map above, but for gids.
    gid_range = (100000, 65536)

    # Set the current working directory to this inside the jail
    cwd = "/"

    # The following variables specify what to execute after chrooting into the jail
    # -----------------------------------------------------------------------------

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
