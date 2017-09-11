# Chroot without root priviledges.

`uchroot.py` is a very simple script that demonstrates the use of linux user
namespaces and mount namespaces to create chroot jails without root. It's not
entirely a no-root solution because it requires the newuidmap and newgidmap
set-uid-root helper functions (on ubuntu, installed with the uidmap package).
This requirement is not really necessary if you only need to enter the chroot
jail with a single user id mapped.

# Requirements

Install `newuidmap` ubuntu package.

# Example usage

Let's create a simple ubuntu `trusty` `arm64` container that we can run under
emulation on an `amd64` (i.e. `x64`) system using `multistrap` and `uchroot`.

## Fix multistrap

Multistrap is a one-file perl script that does a similar job as `debootstrap`
but works well for cross-architecture bootstrapping. There's a bug in multistrap
distributed with `trusty` which can be fixed with the patch in
`demo/multistrap.patch`. First install the `multistrap` package, and then patch
the script.

On a trusty system, assuming you've cloned this repo into your home directory,
run the following:

    :~$ sudo apt-get install multistrap
    :~$ cd /tmp
    :/tmp$ cp /usr/sbin/multistrap ./
    :/tmp$ patch-p0 < ~/uchroot/demo/multistrap.patch

## Bootstrap the rootfs

Multistrap takes a config file. For this demo, use the config file in the repo
as `demo/trusty_arm64.conf`. Execute multistrap with (assuming you patched it,
otherwise just use `multistrap`):

    /tmp/multistrap -f demo/trusty_arm64.conf

You should see

    ...
    I: Extracting ubuntu-keyring_2012.05.19_all.deb...
    I: Extracting zlib1g_1%3a1.2.8.dfsg-1ubuntu1_arm64.deb...
    I: Unpacking complete.
    I: Tidying up apt cache and list data.
    I: Tidying up apt cache and list data.

    Multistrap system installed successfully in /tmp/trusty_arm64/.

## Tweak the rootfs

When using multistrap, there are often a number of configuration hacks required
to get dpkg to configure packages correctly. For this minimal rootfs we need the
following tweaks:

    :~/uchroot$ ln -s ../usr/lib/insserv/insserv /tmp/trusty_arm64/sbin/insserv
    :~/uchroot$ ln -s mawk /tmp/trusty_arm64/usr/bin/awk
    :~/uchroot$ cp demo/sources-arm64.list /tmp/trusty_arm64/etc/apt/sources.list
    :~/uchroot$ cp demo/base_files.patch /tmp/trusty_arm64/
    :~/uchroot$ rm /tmp/trusty_arm64/etc/apt/sources.list.d/multistrap*


## Enter the container


Now use the config file in `demo/trusty_arm64.json` to `uchroot` into the
rootfs:

    :~/uchroot$ python uchroot.py demo/trusty_arm64.json

## Finish up a few tweaks and configure packages

You should see a root shell prompt (don't worry about "i-have-no-name"). Let's
finish configuring the rootfs

    :/# /var/lib/dpkg/info/dash.preinst install
    :/# echo "dash dash/sh boolean true" > debconf-set-selections
    :/# echo "America/Los_Angeles" > /etc/timezone
    :/# patch -p0 < base_files.patch
    :/# rm base_files.patch
    :/# dpkg --configure -a

You should see lots of messages for install hooks and package setup. There seems
to be a problem where `python-minimal` may be configured before `/etc/passwd`
and `/etc/groups` is written, so you'll probably see:

    Errors were encountered while processing:
     python2.7-minimal
     python-minimal
     python
     python2.7

Just run `dpkg --configure -a` again, and you should see:

    Setting up python2.7-minimal (2.7.6-8) ...
    Setting up python-minimal (2.7.5-5ubuntu3) ...
    Setting up python2.7 (2.7.6-8) ...
    Setting up python (2.7.5-5ubuntu3) ...

## Play!

You can now exit the `uchroot`, and then re-enter and you're all set up with a
minimal trusty `arm64` emulated system. Install packages as usual with `apt`.
For instance

    :/# apt-get update
    :/# apt-get install python-pip

When you exit the chroot, take a look through the filesystem. Anything that
would have been owned by root inside the container is owned by your user outside
the container. Otherwise, note that all the files are owned by users with very
high `uid` and `gid`. They are the mapped ids inside the user namespace. To
understand what the system would have looked like if you really were root,
subtract `100000` from all of the uids and gids.


