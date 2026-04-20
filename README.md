# sigtree.pl

A file integrity monitoring tool for OpenBSD, Linux, and macOS, inspired by
the original Tripwire. Creates cryptographically signed records ("specs") of
filesystem state and detects unauthorized or unexpected modifications.

Primary platform is OpenBSD, where it makes fullest use of pledge/unveil,
immutability flags, and privilege separation. Also runs on Linux and macOS.

Available at https://www.discord.org/lippard/software/ and
https://github.com/lippard661/sigtree

The OpenBSD package sigtree-1.23a.tgz is signed with signify. To verify:
```
signify -C -p discord.org-2026-pkg.pub -x sigtree-1.23a.tgz
```
Public key: https://www.discord.org/lippard/software/discord.org-2026-pkg.pub

(Last version without dependency on Signify.pm or Parallel::ForkManager is 1.18d.)

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
- Protected with user immutability flags (uchg on OpenBSD)
- Not signed (signing optional)
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
- **SHA-2 and SHA-3**: configurable digest algorithm and key length
- **macOS application support**: -m option to suppress application bundle
  contents while still processing them

## Monitored Attributes (Keywords)

```
type            file type (file, dir, link, fifo, device, socket)
linktarget_type type of a symlink's target
uid             owner user ID
gid             owner group ID
mode            file permissions
size            size in bytes
nlink           number of hard links
link            symlink target
mtime           modification time
mtimestasis-NN[smhd]  alert if mtime has NOT changed for NN seconds/minutes/hours/days
ctime           inode change time
shadigest       SHA-2 or SHA-3 digest (algorithm set globally)
flags           filesystem flags (chflags on BSD, chattr on Linux)
ignore          exclude this file/tree from monitoring entirely
```

Default if no keywords specified: all of the above except mtimestasis.

## Commands

```
initialize        Create specs for configured trees
initialize_specs  Create the spec-of-specs for the spec directory
check             Compare current filesystem to stored specs; report changes
check_specs       Check the spec-of-specs for changes
check_file <f>    Check a single file against its spec
update            Update specs to reflect changes found by check
changes           Show pending changes from last check before update
```

On initialize, the sigtree spec-of-specs is written and signed last,
ensuring a valid signed spec implies all tree specs were successfully
written. On update, the spec-of-specs is also updated last.

The changes command shows what check found before you commit to an update —
review this before running update. For partial updates, only updated trees
are removed from the pending changes file; unreviewed changes in other
trees are preserved.

## Options

```
-r root_dir       Root directory for specs (default: /var/db/sigtree)
-c config_file    Config file (default: <root_dir>/<hostname>.sigtree.conf)
-d spec_dir       Spec directory, absolute or relative to root_dir;
                  "secondary" is special-cased to <root_dir>/secondary/<hostname>
-s set_list       Comma-separated list of sets to operate on
-f N              Number of child worker processes
-m                Don't show macOS application bundle contents
-p                Use privilege separation (_sigtree user required)
-v                Verbose: show old and new values of changed attributes
-V                Show version
-h                Help
```

## Installation

### Recommended: OpenBSD signed package

```
pkg_add ./sigtree-1.23a.tgz
```

Or using [install.pl](https://github.com/lippard661/distribute) on OpenBSD,
Linux, or macOS.

### Dependencies

Required:
- Perl 5
- CPAN modules: Digest::SHA, Sys::Hostname, Getopt::Std, File::Basename,
  File::Temp (OpenBSD::MkTemp on OpenBSD), Cwd, Storable
  (all included with OpenBSD standard distribution)
- Digest::SHA3 (CPAN)
- Parallel::ForkManager 1.19 or later (CPAN)
- OpenBSD::Pledge, OpenBSD::Unveil, OpenBSD::MkTemp (OpenBSD only)

For signify signing (recommended):
- [Signify.pm](https://github.com/lippard661/Signify)
- signify (standard on OpenBSD), signify-openbsd (Linux apt package),
  or signify via Homebrew (macOS)

For privilege separation:
- IO::Socket, IO::Handle, IO::Select, IO::FDPass, MIME::Base64,
  Privileges::Drop, JSON::MaybeXS or JSON::PP
- Note: Privileges::Drop requires a small patch on macOS with the
  system perl (5.34.1); works correctly with Homebrew perl

For GPG/PGP signing (optional, signify preferred):
- GPG or PGP 5 or later
- PGP::Sign (CPAN; security/p5-PGP-Sign in OpenBSD ports)
- GPG2 with privsep requires the provided gpg-noagent shell script

For immutability flag support:
- OpenBSD/BSD: /usr/bin/chflags, /usr/sbin/sysctl
- Linux: /usr/bin/chattr, /usr/bin/lsattr

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
```

Copy the sample config from etc/ to /var/db/sigtree/<hostname>.sigtree.conf
and edit to reflect the trees you want to monitor.

## Configuration

The config file has three sections: global attributes, set definitions,
and tree list. Lines beginning with # are comments.

**Global attributes**:
```
crypto-sigs: signify          # signify, GPG, GPG1, or PGP
signify_pubkey: /path/to/pub
signify_seckey: /path/to/sec
immutable-specs: schg         # schg, uchg, yes (=schg), or no
sha2_digest: 256              # 256, 384, or 512
sha3_digest: 256              # 224, 256, 384, or 512 (default if unset)
max_child_procs: 5
default_child_procs: 4
privsep: yes
```

**Set definitions**:
```
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
exception: /etc/mtab:IGNORE
exception-tree: /etc/cups:IGNORE

tree: /usr/local/bin:weekly,daily

tree: /var/log:logs
```

`exception` applies to a single file or directory; `exception-tree` applies
to a directory and all its contents. Specifying `.` as an exception changes
the primary set of the tree's root directory itself without affecting its
contents — useful for directories like /etc whose mtime/ctime changes
frequently.

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

## Security Notes

- Spec files and the sigtree config should be owned by root and not
  world-readable (0600); they reveal exactly what is and isn't monitored
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
