=========
Changelog
=========

------
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
