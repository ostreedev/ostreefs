Ostreefs
========

ostreefs is a kernel filesystem that mounts ostree commits directly
from an on-disk (bare format) ostree repository, with the goal of
continuous verification of the ostree content. In other words, protect
against any changes to the data in the filesystem as specified by
the ostree commit id either online or offline.

## Short background on ostree repos

A normal booted ostree system contains two parts, a repository and a
checkout of a commit from the repository.

The repository has is a directory of "object files" which are indexed
by the sha256 of their content and metadata. Some object files
describe directories, and some regular files. There are also commit
objects that contain a reference to the root directory. The regular
file objects look just like the real files on disk (apart from the
name), but the others are in a custom file format.

To be able to use such a repo ostree makes a checkout of the
commit. This converts the directory metadata files to actual regular
directories the kernel can understand, with the regular files in them
being hard-links to the files in the repo.

All the object files in the repository are verified by comparing the
actual checksum with the expected one during download. In addition
the commit object can be verified against a gpg signature.

When the system is booted, the checkout for the commit we're booting
is bind-mounted read-only as the root filesystem.

## Verification issues with ostree

Once an ostree commit has been downloaded and checked out on disk, we
never do any further verifications. This means that an attacker
changing or adding files in the checkout (or accidental changes) will
not be detected.

It is possible to enable fs-verity for the files in the repository,
which will tell the kernel to make the repo files immutable and all
further reads from them will be verified against the stored
checksums. However, this does not prohibit adding or replacing files.

So, while the verification at deploy is nice, we would like to
complete this with *continuous* verification, where every single
I/O operation is verified against the ostree commit digest before
being used.

## Introducing ostreefs

Instead of using a checkout of the commit and hardlinks to the
repostory we use a custom kernel-based filesystem somewhat similar to
overlayfs. It mounts the commit directly from the ostree repo, and
ensures that directory metadata is immutable and verified before used.

For example, suppose you have an ostree repo in /some/repo, and it
contains a commit with id
`f163640407d292e262442ab76af6eca4e2722d54c081c7be6e005114a57057dd`. Then
you can mount this at `/mnt/ostree` by specifing the commit and the
object directory from the repo as mount options, like this:

```
# mount ostreefs -t ostreefs -o commit=f163640407d292e262442ab76af6eca4e2722d54c081c7be6e005114a57057dd,objectdir=/some/repo/repo/objects /mnt/ostree
# ls -l /mnt/ostree
total 0
lrwxrwxrwx. 1 root root    0 Jan  1  1970 bin -> usr/bin
drwxr-xr-x. 1 root root 4096 Jan  1  1970 boot
drwxr-xr-x. 1 root root 4096 Jan  1  1970 dev
lrwxrwxrwx. 1 root root    0 Jan  1  1970 home -> var/home
lrwxrwxrwx. 1 root root    0 Jan  1  1970 lib -> usr/lib
lrwxrwxrwx. 1 root root    0 Jan  1  1970 lib64 -> usr/lib64
lrwxrwxrwx. 1 root root    0 Jan  1  1970 media -> run/media
lrwxrwxrwx. 1 root root    0 Jan  1  1970 mnt -> var/mnt
lrwxrwxrwx. 1 root root    0 Jan  1  1970 opt -> var/opt
lrwxrwxrwx. 1 root root    0 Jan  1  1970 ostree -> sysroot/ostree
drwxr-xr-x. 1 root root 4096 Jan  1  1970 proc
lrwxrwxrwx. 1 root root    0 Jan  1  1970 root -> var/roothome
drwxr-xr-x. 1 root root 4096 Jan  1  1970 run
lrwxrwxrwx. 1 root root    0 Jan  1  1970 sbin -> usr/sbin
lrwxrwxrwx. 1 root root    0 Jan  1  1970 srv -> var/srv
drwxr-xr-x. 1 root root 4096 Jan  1  1970 sys
drwxr-xr-x. 1 root root 4096 Jan  1  1970 sysroot
drwxrwxrwt. 1 root root 4096 Jan  1  1970 tmp
drwxr-xr-x. 1 root root 4096 Jan  1  1970 usr
drwxr-xr-x. 1 root root 4096 Jan  1  1970 var
```

## Building ostreefs

Before using ostreefs you must build the ostreefs kernel module against the kernel sources
matching the version you are running. On Fedore and CentOS this is available in the
kernel-devel package as /usr/src/kernels/$kernelversion, other distributions may
have a different location.

To build and load the ostreefs module, then run:

```
# make -C /usr/src/kernels/$(uname -r) modules M=$PWD
# insmod ostreefs.ko
```

## SELinux issues

Ostreefs support xattrs natively, and selinux normally uses xattrs to
store selinux file contexts. However, this only works if the local
policy allows a particular filesystem type to use xattrs for selinux,
and the default is to not allow it. So, until the default selinux
contexts supports ostreefs, you need to manually install a local
policy for this.

To enable ostreefs selinux support, run:

```
# semodule -i ostreefs.cli
```

And, to later revert it, run:

```
# semodule -r ostreefs
```

## Verification status

Ostreefs currently verifies the sha256 checksum of the commit, dirmeta
and dirtree objects, which means all directory content is guaranteed to
match the commit.

However, content and metadata for regular files and symlinks is not
currenly verified. Work is ongoing to support this though.
