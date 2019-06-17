=========
Changelog
=========

-----------
v0.1 series
-----------

v0.1.4
------

* remove newlines from log messages
* add inotify and signalfd apis to glibc ctypes wrapper
* if binary executable is not specified but argument vector is specified, then
  use first element of argument vector as binary executable
* if binary executable starts with forward slash, don't use use exec version
  that does path lookup
* update dump_constants helper to output in python, json, or human format
* automatically load config file from the root of the target filesystem
* update documentation theme to something based on rtd

v0.1.3
------

* Intercept requests for /proc mount and use the MS_REC flag on those
* "allow" `setgroups` as it is now used by apt-get

v0.1.2
------

* Add argparse remainder so that argv can be specified more conveniently in
  command line execution.
* Increase information included in warning of mount failure

v0.1.1
------

* Assert newuidmap helper programs exist before forking for easier debug
* Add config VARDOCS, argparse helpstrings, and --dump-config command line
  options

v0.1.0
------

Initial publication. This script has been in use in various places for
around a year in various incarnations. Hopefully it is useful to others.

* Enter a chroot with a user and mount namespace
* Optionally bind mount filesystem components into the target fs after
  creating the mount namespace and before chroot. This means that these
  mounts are invisible outside the call to uchroot.
* Optionally copy a qemu binary into the target rootfs before chrooting.
  This can be used to uchroot a foreign architecture rootfs.
