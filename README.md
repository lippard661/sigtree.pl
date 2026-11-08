# sigtree.pl

A file integrity monitoring tool for OpenBSD, Linux, and macOS, inspired by
the original Tripwire. Creates cryptographically signed records ("specs") of
filesystem state and detects unauthorized or unexpected modifications.

Primary platform is OpenBSD, where it makes fullest use of pledge/unveil,
immutability flags, and privilege separation. Also runs on Linux and macOS.

Available at https://www.discord.org/lippard/software/ and
https://github.com/lippard661/sigtree

The OpenBSD package sigtree-&lt;version&gt;.tgz is signed with signify. To verify:
```
signify -C -p discord.org-2026-pkg.pub -x sigtree-<version>.tgz
```
Public key: https://www.discord.org/lippard/software/discord.org-2026-pkg.pub

(Last version without dependency on Signify.pm or Parallel::ForkManager is 1.18d.
Version 1.26 and later require Signify.pm 1.4 or later when signify is used.)

## Overview

sigtree.pl creates a "specification" (spec) for each monitored directory tree,
recording selected file attributes. Subsequent checks compare the current
filesystem state to the stored spec and report changes. Specs can be
cryptographically signed (signify recommended; GPG/PGP also supported) and
optionally protected with filesystem immutability flags.

Files and directories are organized into named sets which determine what
attributes are monitored. Exceptions within a tree can be assigned different
sets, or excluded entirely with IGNORE.

## Recommended Deployment: Dual Spec Architecture

The recommended approach is two independent sets of specs per host:

**Primary specs** (`/var/db/sigtree/specs/<hostname>/`):
- Protected with system immutability flags (schg on OpenBSD)
- Signed with signify
- Checked weekly (Friday night recommended)
- Initialize and update require single-user mode on OpenBSD
- Comprehensive — monitors all trees in the "weekly" set

**Secondary specs** (`/var/db/sigtree/secondary/<hostname>/`):
- Protected with user immutability flags (uchg on OpenBSD/BSD; no
  immutability flag on Linux)
- Never signed: `-d secondary` turns signing off whatever crypto_sigs says,
  so daily updates need no passphrase
- Checked and auto-updated daily; full check Wednesday night
- Monitors a critical subset ("daily" set) daily, full "weekly" set Wednesday

Staggering the weekly checks (e.g., primary Friday, secondary Wednesday)
ensures no more than a few days pass without a comprehensive check by one
or the other. The auto-update of secondary specs after each check keeps
the daily baseline current without manual intervention.

Specs are stored under hostname subdirectories, making it straightforward
to rsync specs from multiple hosts to a central server for aggregation.

## Features

- **Parallel operation**: initialize and check run worker child processes
  for speed, controlled by max_child_procs and default_child_procs settings
- **Privilege separation**: privileged process handles directory listing,
  stat, and opening file handles; unprivileged _sigtree workers compute
  SHA hashes. Uses pledge/unveil on OpenBSD with additional ratcheting
  after fork and privilege drop.
- **Cryptographic signing**: signify (recommended), GPG, or PGP. Signs
  each spec file and a master spec-of-specs for the spec directory.
- **Immutability flag support**: schg or uchg on OpenBSD/BSD; +i on Linux
- **mtimestasis**: monitors for files that have NOT changed within a
  specified time window — useful for detecting silenced log files
- **SHA-2 and SHA-3**: configurable digest algorithm and digest length
- **macOS application support**: -m option to suppress application bundle
  contents while still processing them

## Monitored Attributes (Keywords)

```
type            file type (file, dir, link, block device, char device, fifo, socket)
linktarget_type type of a symlink's target
uid             owner user ID
gid             owner group ID
mode            file permissions
size            size in bytes
nlink           number of hard links
link            symlink target
mtime           modification time
mtimestasis-NN[smhd]  alert if mtime has NOT changed for NN seconds/minutes/hours/days
                (NN is one or two digits)
ctime           inode change time
shadigest       SHA-2 or SHA-3 digest (algorithm set globally, default 256-bit SHA-3)
flags           filesystem flags (chflags on BSD, chattr on Linux)
ignore          exclude this file/tree from monitoring entirely
```

Default if no keywords specified:
`type,uid,gid,mode,size,nlink,link,mtime,ctime,shadigest,flags`
(that is, everything above except linktarget_type, mtimestasis, and ignore).

## Commands

```
initialize        Create specs for configured trees
initialize_specs  Create the spec-of-specs for the spec directory
check             Compare current filesystem to stored specs; report changes
check_specs       Check the spec-of-specs for changes
check_file <f>    Check a single file against its spec
update            Update specs to reflect changes found by check
changes           Show pending changes from last check before update
verify_hosts      On a central server, check copies of other hosts' databases
```

On initialize and update, the sigtree spec-of-specs is written and signed
last, after the tree specs. It records the spec directory as it is at that
point, so a good signature on it does not by itself mean every tree spec
was written: if a tree failed, sigtree says so and exits non-zero (and that
tree's pending changes are kept). Check the exit status, or the output, of
initialize and update.

The changes command shows what check found before you commit to an update —
review this before running update. For partial updates, only updated trees
are removed from the pending changes file; unreviewed changes in other
trees are preserved.

sigtree exits non-zero when a command fails, including when one tree's
worker fails (the other trees are still processed and the failed tree's
pending changes are kept), when signing fails, or when an immutability
flag cannot be set or reset. initialize and update test the passphrase
by signing a temporary file before changing any spec, so a mistyped
passphrase changes nothing.

## Options

```
-r root_dir       Root directory for specs (default: /var/db/sigtree)
-c config_file    Config file (default: /etc/<hostname>.sigtree.conf; a
                  relative path is taken relative to /etc unless it
                  starts with ./)
-d spec_dir       Spec directory, absolute or relative to root_dir;
                  "secondary" is special-cased to <root_dir>/secondary/<hostname>
                  (with an absolute path, the spec-of-specs and changed
                  file go in its parent directory)
-s set_list       Comma-separated list of sets to operate on; with
                  initialize, "new" (or "uninitialized") selects trees
                  that have no spec yet. Not allowed with
                  initialize_specs, check_specs, or check_file.
-f N              Number of child worker processes: 0 (no workers) or
                  2 up to max_child_procs. Only for initialize and check.
-m                Don't show macOS application bundle contents
-p                Use privilege separation (must run as root; _sigtree
                  user and group required); same as "privsep: yes"
-v                Verbose: show old and new values of changed attributes
-V                Show version (alone, with no other option or command)
-h                Help
-D                Debugging output
```

## Installation

### Recommended: OpenBSD signed package

```
pkg_add ./sigtree-<version>.tgz
```

Or using [install.pl](https://github.com/lippard661/distribute) on OpenBSD,
Linux, or macOS.

### Dependencies

Required:
- Perl 5.10 or later
- Core Perl modules: Digest::SHA, Sys::Hostname, Getopt::Std, File::Basename,
  File::Temp (OpenBSD::MkTemp on OpenBSD), Cwd, Storable, IO::Socket,
  MIME::Base64 (all included with Perl and with OpenBSD's base system)
- Digest::SHA3 (CPAN)
- Parallel::ForkManager 1.19 or later (CPAN), unless workers are turned
  off (-f 0 and default_child_procs: 0)
- OpenBSD::Pledge, OpenBSD::Unveil, OpenBSD::MkTemp (OpenBSD only)

For signify signing (recommended):
- [Signify.pm](https://github.com/lippard661/Signify) 1.4 or later
- signify (standard on OpenBSD), signify-openbsd (Linux apt package),
  or signify via Homebrew (macOS)

For privilege separation:
- Run as root, with a _sigtree user and group
- IO::Handle, IO::Select, JSON::MaybeXS or JSON::PP (core), and
  IO::FDPass and Privileges::Drop (CPAN)
- Note: Privileges::Drop requires a small patch on macOS with the
  system perl (5.34.1); works correctly with Homebrew perl

For GPG/PGP signing (optional, signify preferred):
- GPG or PGP 5 or later
- PGP::Sign (CPAN; security/p5-PGP-Sign in OpenBSD ports)
- GPG2 with privsep requires the provided gpg-noagent shell script,
  installed as /usr/local/bin/gpg-noagent

For immutability flag support:
- OpenBSD/BSD: /usr/bin/chflags, /sbin/sysctl, /bin/ls
- macOS: /usr/bin/chflags, /usr/sbin/sysctl, /bin/ls
- Linux: /usr/bin/chattr, /usr/bin/lsattr, /usr/bin/stat

Install CPAN modules via OpenBSD ports, Homebrew, apt, or:
```
perl -MCPAN -e shell
install Digest::SHA3
install Parallel::ForkManager
install Privileges::Drop
```

### Manual installation

```sh
cp src/sigtree.pl /usr/local/bin/
chmod 755 /usr/local/bin/sigtree.pl
mkdir -p /var/db/sigtree
chmod 700 /var/db/sigtree
```

Copy the sample config from etc/ to /etc/<hostname>.sigtree.conf (owned by
root, mode 0600; sigtree refuses a config that is group- or world-writable
or owned by another user) and edit it to reflect the trees you want to
monitor. `<hostname>` is the short host name, as `hostname -s` prints it.

For signify, create a key pair (sigtree's default paths are shown; others
can be set with signify_seckey and signify_pubkey):
```sh
signify -G -p /etc/signify/sigtree.pub -s /etc/signify/sigtree.sec
```

Then create the specs with `sigtree.pl initialize`.

## Configuration

The config file has three sections, in this order: global attributes, set
definitions, and tree list. Lines beginning with # are comments; a # later
in a line is not a comment, so values cannot have trailing comments.

**Global attributes**:
```
crypto_sigs: signify
signify_pubkey: /etc/signify/sigtree.pub
signify_seckey: /etc/signify/sigtree.sec
immutable-specs: schg
sha3_digest: 256
max_child_procs: 5
default_child_procs: 4
privsep: yes
```

- `crypto_sigs`: signify, GPG (GPG 2), GPG1, PGP, or none. If omitted,
  specs are signed only if `pgpkeyid` is set (GPG 2, or signify if
  `pgpkeyid: signify`).
- `signify_pubkey`, `signify_seckey`: default to /etc/signify/sigtree.pub
  and /etc/signify/sigtree.sec. The files must exist and be readable.
- `pgpkeyid`, `pgpkeyring`: key ID and keyring directory for GPG/PGP
  (keyring default /root/.gnupg for GPG, /root/.pgp for PGP).
- `immutable-specs`: schg, uchg, yes, or no. schg and uchg are BSD/macOS
  only; yes means schg on BSD/macOS and +i on Linux.
- `sha2_digest` (256, 384, or 512) or `sha3_digest` (224, 256, 384, or
  512), not both. Default is 256-bit SHA-3.
- `max_child_procs`, `default_child_procs`: 0 or 2 and up (defaults 5 and
  4); default must not exceed max.
- `privsep`: yes or no.

**Set definitions**:

Each set is `set: longname,shortname` (both names required, at most 12
characters each), followed by a required `description:`, optional
`keywords:` (default list above), and optional `priority:` (reports list
sets highest priority first). A set named `sigtree` must be defined; it is
used for sigtree's own spec directory.
```
set: sigtree,SIG
description: Sigtree files.
keywords: gid,mode,nlink,shadigest,uid,size,link,mtime,ctime,type,linktarget_type
priority: 500

set: weekly,wk
description: Weekly comprehensive check.
keywords: type,uid,gid,mode,size,nlink,link,mtime,ctime,shadigest,flags
priority: 10

set: daily,dy
description: Daily check of critical files.
keywords: type,uid,gid,mode,size,nlink,link,mtime,ctime,shadigest,flags
priority: 10

set: logs,lg
description: Log files -- no hash, monitor for stasis.
keywords: type,uid,gid,mode,size,nlink,mtime,mtimestasis-24h,flags

set: IGNORE,IG
description: Files to ignore entirely.
keywords: ignore
```

**Tree list**:
```
tree: /etc:weekly,daily
exception: mtab:IGNORE
exception-tree: cups:IGNORE

tree: /usr/local/bin:weekly,daily

tree: /var/log:logs

tree: /var/www:weekly,daily
primary-exception-tree: logs:IGNORE
secondary-exception-tree: logs:logs
```

A tree takes a list of sets; the first is its primary set, which decides
which keywords are checked, and the others group trees for `-s`.
`exception` applies to a single file or directory; `exception-tree` applies
to a directory and all its contents. Exception paths are relative to the
tree (`mtab`, not `/etc/mtab`; an absolute path is a config error), and
each exception takes one set.
Exceptions are only allowed for trees that are directories. Specifying
`.` as an exception changes the primary set of the tree's root directory
itself without affecting its contents — useful for directories like /etc
whose mtime/ctime changes frequently.

`primary-exception`, `secondary-exception`, `primary-exception-tree` and
`secondary-exception-tree` work like `exception` and `exception-tree`, but
apply only to primary specs (any run without `-d secondary`) or only to
secondary specs. They are for paths that need a different set in each:
above, web logs that must change daily are checked for stasis in the
secondary specs but ignored in the primary specs, which are made in
single-user mode when the web server is not running. A path has either an
`exception` line, shared by both kinds of specs, or per-mode lines, not
both. Lines for the other kind of specs are still checked for errors, but
a missing path is only warned about for the kind being run. (Added in
sigtree 1.28.)

Trees may not overlap; no tree may be a subtree of another tree in the config.
Symbolic links are never followed to avoid loops.

## Recommended Cron Setup

In `/etc/daily.local` (OpenBSD) or equivalent:
```sh
host=`/bin/hostname -s`
dayofweek=`/bin/date +"%a"`
changedfile="/var/db/sigtree/secondary/$host.changedsec"
case $dayofweek in
    Wed) sigtreetest="daily,weekly" ;;
    *)   sigtreetest="daily" ;;
esac
/usr/bin/perl /usr/local/bin/sigtree.pl -d secondary -s $sigtreetest check | \
    mail -s "$sigtreetest $host secondary sigtree report" your@email
test -f $changedfile && \
    /usr/bin/perl /usr/local/bin/sigtree.pl -d secondary -s $sigtreetest update
```

In `/etc/weekly.local` (OpenBSD) or equivalent (run on a different day
than secondary weekly check):
```sh
host=`/bin/hostname -s`
/usr/bin/perl /usr/local/bin/sigtree.pl check | \
    mail -s "weekly $host sigtree report" your@email
```

Add `-v` for verbose output showing old and new values of changed attributes.

## Checking Hosts from a Central Server

If each host's `/var/db/sigtree` is copied to a central server (and backed
up there with rsnapshot), `sigtree verify_hosts` on that server checks the
copies with its own config file (`/etc/sigtree.hosts.conf`, or `-c`; see
`sigtree.hosts.conf.sample`). Added in sigtree 1.29. For each host it
reports:

- how long ago the host's primary changed file was written (its mtime is
  the time of the host's last check that found changes), or that there is
  none (normal the day after an update);
- spec files that changed between the previous and current snapshots, and
  any changed spec that is byte for byte a copy from an older snapshot: a
  validly signed old spec put back, which no signature check can catch;
- for a host whose signify public key is pinned in the config, any spec or
  spec-of-specs whose signature does not verify;
- among hosts marked as peers (same OS release), files under the
  configured common paths that differ from what most peers have, that one
  host lacks, or that only one host has.

It prints nothing when there is nothing to report, so it can run from
`/etc/daily.local` on the central server:
```sh
/usr/bin/perl /usr/local/bin/sigtree.pl verify_hosts
```

A host's spec is loaded only after its signature has verified, and then
only in a process running as `_sigtree`: specs are written by the hosts,
which might be compromised. Nothing else a host wrote is loaded; the
changed file is judged by its mtime and the snapshots by size and hash.
Hosts that sign with GPG get the changed-file and snapshot checks but not
the signature checks or the comparison.

## Security Notes

- Spec files and the sigtree config (/etc/<hostname>.sigtree.conf) should
  be owned by root and not world-readable (0600); they reveal exactly what
  is and isn't monitored
- The /var/db/sigtree directory tree should not be world-traversable
- Primary specs with schg immutability require single-user mode on OpenBSD
  for initialize and update operations
- Consider using [syslock](https://github.com/lippard661/syslock) for
  managing immutability flags on the broader system; sigtree manages its
  own spec file flags internally
- Specs stored under /var/db/sigtree/specs/<hostname> and
  /var/db/sigtree/secondary/<hostname> can be rsynced to a central host
  for aggregation across multiple systems

## Related Tools

- [syslock](https://github.com/lippard661/syslock) — filesystem immutability flag management
- [distribute](https://github.com/lippard661/distribute) — secure file distribution and installation
- [reportnew](https://github.com/lippard661/reportnew) — log and process accounting monitoring
- [rsync-tools](https://github.com/lippard661/rsync-tools) — secure automated rsync operations
- [Signify](https://github.com/lippard661/Signify) — Perl wrapper for OpenBSD signify

## Author

Jim Lippard  
https://www.discord.org/lippard/  
https://github.com/lippard661

Bug reports and suggestions: lippard-sigtree@discord.org

## License

See individual files for license information.

## Changelog

See docs/ChangeLog for detailed modification history.
