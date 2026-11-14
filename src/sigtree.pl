#!/usr/bin/perl
#
#########################################################################
#
# Copyright 2000-2026 by Jim Lippard.  Permission granted for free
# distribution, commercial and non-commercial use, with the proviso that
# this notice remain intact and that any sale of this software or any
# package or system or service which includes this software or any
# substantial part of this software as a part, requires payment of a
# license fee.  If you are a consultant being paid to install this
# software on a system, you must pay the license fee.  If you are selling
# CD-ROMs which include this software at a cost greater than the cost of
# production and distribution, you must pay the license fee.  For
# licensing information, contact lippard-sigtree@discord.org.
#
#########################################################################
# Script to create, check, and update specifications of particular
# directory trees, optionally PGP signing them and setting their
# immutable flags.
#
# Home website location is https://www.discord.org/lippard/software.
#
# Written 18-30 January 2000 by Jim Lippard, based on my previous
#    mtree.pl script of 1 January 1999.
# Modified 5 February 2000 by Jim Lippard to check for file existence
#    before doing chflags and record username in specs and changed file.
# Modified 6 February 2000 by Jim Lippard to fix "new nonexistent added"
#    problem and problem with overlooking trees that have only additions or
#    deletions in check summary report.
# Modified 11 February 2000 by Jim Lippard to fix bug in reg exp for
#    validating "tree:" lines in conf file.
# Modified 12 February 2000 by Jim Lippard to make config check to make
#    sure no trees are subtrees of other trees, check to make sure the
#    specified list of sets contains at least one tree, and to add
#    check_file command.  Also fixed a bug which would cause check to
#    claim no changes were found if there were only files added or
#    deleted.
# Modified 28 March 2000 by Jim Lippard to use Linux chattr for
#    immutable files.
# Modified 2 April 2000 by Jim Lippard to add "ignore" keyword.  Any
#    file in a set with that keyword will not be checked for any changes.
# Modified 3 March 2001 by Jim Lippard to make GPG support work.
# Modified 6 January 2003 by Jim Lippard to support BSD file system flags, add
#    exception-tree and redefine exception, add -v to "changes" command, allow
#    "." for exception (and refuse ".."; refuse either for "exception-tree").
# Modified 9 January 2003 by Jim Lippard to fix bug in changed file package.
# Modified 22 January 2003 by Jim Lippard to fix a bug introduced 9 January 2003.
# Modified 22 February 2003 by Jim Lippard to make "changes" show list
#    of changed attributes.
# Modified 23 February 2003 by Jim Lippard to check writability of specs
#    before writing to them and to verify if resetting immutable flags works.
# Modified 25 February 2003 by Jim Lippard to improve Linux support of
#    immutable flags, change treatment of -d option to allow absolute
#    or relative path, and special-case -d secondary to not use PGP-signing
#    or immutable flags and to use a separate changed file.
# Modified 26 February 2003 by Jim Lippard to use $spec_dir_dir instead
#    of $root_dir/specs and use different specifications dir specification
#    for secondary specifications.  Fixed bug in writable_file when file
#    doesn't exist.
# Modified 5 January 2004 by Jim Lippard to not generate SHA1 digests for
#    directories, which Digest::SHA1 has never supported but no longer silently
#    fails on.
# Modified 10 June 2004 by Jim Lippard to use variable for sysctl and
#    update for OpenBSD's new location (/sbin instead of /usr/sbin) in
#    OpenBSD 3.5, also accounting for change in output format.
# Modified 14 July 2004 by Jim Lippard to fix bug in show_changes subroutine
#    where it was trying to display changed attributes by tree.
# Modified 16 July 2004 by Jim Lippard to allow check_file even for nonexistent
#    files (since they may be in the spec but not in the file system).  Fixed bug
#    in FileAttr::compare which was occasionally causing deleted files to show up
#    as added.
# Modified 26 August 2004 by Jim Lippard to move file type setting to a separate
#    subroutine and to track attributes of link targets (but currently not functioning
#    for directory contents or SHA1 digests).  Fixed some minor bugs.
# Modified 2 September 2004 by Jim Lippard to test results of getting file flags
#    and set to "<undefined>" if no result was returned.
# Modified 3 September 2004 by Jim Lippard to test $self->{LINKTARGET_TYPE} for
#    being defined before use, for backward compatibility with old specs where
#    it isn't defined.
# Modified 7 March 2005 by Jim Lippard to allow use of SHA2 instead of or in addition to SHA1.
# Modified 22 November 2008 by Jim Lippard to not create subtrees that are supposed to be
#    ignored.  Removed configuration setting for SHA1/SHA2; only compute SHA1 or SHA2 based
#    on keywords in applicable sets.
# Modified 25 December 2011 by Jim Lippard to allow creation of a new
#    spec in an existing specs dir even if the latter is immutable.  Fixed
#    bug in immutable_file which had BSD and Linux checks reversed.  Added
#    option to select system or user immutability in BSD. (Not sure what
#    configuration setting for SHA1/SHA2 was supposedly removed--the main
#    config setting is still there.)  $root_dir is now just the location
#    of specs and changed files but NOT the config file.  Defaults
#    are now /etc/<hostname.conf> for the config file and /var/db/sigtree
#    for specs and change files; the conf file is thus no longer in the
#    sigtree set by default but is covered by /etc.
# Modified 17 March 2012 by Jim Lippard to add parentheses to escaped characters in
#    $full_path prior to getting file flags.
# Modified 3 November 2012 by Jim Lippard to use Digest::SHA instead of
#    Digest::SHA1 and Digest::SHA2. Removed support for SHA1, added for
#    384-bit and 512-bit in addition to default of 256-bit.
# Modified 10 November 2012 by Jim Lippard to die if hostname is
#    undefined.
# Modified 19 November 2012 by Jim Lippard to avoid double error messages for nonexistent exception-trees (and
#    fix typo in error message/inadvertent lowercasing of the line.
# Modified 25 March 2013 by Jim Lippard to support mtimestasis-\d{1,2}[smhd]
#    keyword on sets, which triggers a report for a lack of change in
#    modification time equal to or greater than the specified number of
#    seconds, minutes, hours, or days, which can be an indicator of
#    something broken or of compromise.
# Modified 10 October 2015 by Jim Lippard to support SHA-3, 256-bit by default.
# Modified 23 December 2015 by Jim Lippard to support flags on Mac OS X.
# Modified 12 November 2017 by Jim Lippard to fix bug in flag support, some macOS X
#    specific, some more general.
# Modified 17 November 2017 by Jim Lippard to fix bug in config file parsing which was
#    preventing use of exception or exception-tree names which had already
#    been used in a previous tree, not the current one.
# Modified 7 October 2018 by Jim Lippard to fix bug in initializing specific sets
#    when a changed file exists.
# Modified 21 December 2018 to (still ongoing) by Jim Lippard to add "interactive".
# Modified 3 August 2019 by Jim Lippard to permit update to update the spec_dir
#    tree itself, while retaining the warning.
# Modified 22 May 2021 by Jim Lippard to not prompt for passphrase with
#    GPG2 (default) and to set GPG_TTY environment variable. The passphrase
#    is prompted for by gpg-agent by signing a temp file.
# Modified 23 May 2021 by Jim Lippard to remove interactive mode additions.
# Modified 21 July 2021 by Jim Lippard to not warn about nonexistent exceptions
#    or exception-trees in the config when their primary set has the "ignore"
#    keyword.
# Modified 26 July 2021 by Jim Lippard to add support for signify in addition
#    to PGP and GPG. New config file settings to select crypto sig type and
#    key locations.
# Modified 17 January 2022 by Jim Lippard to escape "$" found in filenames
#    when looking for immutable flags. (And re-implement 12 March 2012
#    escaping of parentheses, which got commented-out at some point.)
# Modified 20 January 2022 by Jim Lippard to support "-s new|uninitialized"
#    for the initialize command, and make those reserved set names that
#    cannot be used in configs. Part of the "new" set code had already
#    been implemented at some point in the past as preparation for this
#    functionality, but never completed. Changed check/check_specs to report
#    any extraneous files in the specification directory that aren't
#    expected from the trees in the config (e.g., old specs for trees
#    removed from the config). Changed initialize_sets to remove extraneous
#    files from the specification dir.
# Modified 22 January 2022 by Jim Lippard to fix the "$" escaping in both
#    places where it is needed (missed _get_file_flags and didn't have it
#    quite right:  -e requires unescaped, the ls command requires escaped).
#    Remove any trees from the changed file that are no longer in the config.
# Modified 23 January 2022 by Jim Lippard to remove parentheses from
#    escaping when getting file flags--the quotation marks make it
#    not only unnecessary but wrong, escaping is only required for $. Fixed
#    some cosmetic issues with line spacing, and an update issue when handling
#    extraneous files in the spec_dir.
# Modified 18 October 2023 by Jim Lippard to continue when a fileattr cannot
#    be retrieved rather than aborting, which can occur, e.g., when a critical
#    log is mid-rotation and doesn't exist yet.
# Modified 3 December 2023 by Jim Lippard to use pledge and unveil on OpenBSD.
# Modified 9 December 2023 by Jim Lippard for some unveil fixes (need r,
#    not just x, for commands used).
# Modified 16 December 2023 by Jim Lippard to unveil /tmp.
# Modified 28 December 2023 by Jim Lippard to not require pgpkeyid to be
#    set to 'signify' (it can be omitted) when signify is used.
# Modified 30 December 2023 by Jim Lippard to call pledge correctly.
# Modified 2 January 2023 by Jim Lippard to use Storable's advisory lock
#    methods and use newer perl file open style. Fixed a couple error
#    messages about digital signatures.
# Modified 7 January 2023 by Jim Lippard to test properly for signify
#    signatures when they don't already exist and to remove need to
#    put signify passphrases on a command line passed to system or use
#    of echo.
# Modified 8 January 2023 by Jim Lippard to fix bug in verify_required_dirs
#    when checking kernel securelevel.
# Modified 7-10 August 2024 by Jim Lippard to allow forking of child processes
#    to speed up check process. Use OpenBSD::MkTemp for OpenBSD. Use
#    Signify.pm. Allow forking of child processes to speed up initialize
#    process.
# Modified 12 August 2024 by Jim Lippard to add -f option to specify
#    number of child processes and global config settings for
#    max_child_procs and default_child_procs. If child procs are being
#    used, report both the start and end of processing for each tree for
#    both initialize and check. Add -m to not show macOS app dir contents
#    changes (or adds or deletions) from changes, show_changes, or
#    show_change_details, as well as in check_sets/check_tree and
#    update_sets. Change method for quoting args to list command for
#    immutable flags.
# Modified 30 August 2024 by Jim Lippard to fix bugs in both immutable_flags
#    (for BSD!) and _get_file_flags (for Linux).
# Modified 31 August 2024 by Jim Lippard to use lsattr -d on Linux so that
#    dirs don't list flags of contents instead of the directory's flags.
#    Use chattr -f to suppress error messages, don't try to use lsattr
#    on links.
# Modified 12 October 2024 by Jim Lippard to unveil / due to likely
#    presence of symlinks. (Instigated by my own moving of /usr/share/relink
#    to /home due to space considerations.)
# Modified 21 December 2024 by Jim Lippard to change unveil permissions for
#    sigtree dirs (add x), which impacts ability to create initial dirs.
# Modified 27 August 2025 by Jim Lippard to sanitize environment and change
#    system calls to avoid use of shell.
# Modified 6 September 2025 by Jim Lippard to set fork_children to 0 for
#    initialize_specs.
# Modified 13 September 2025 by Jim Lippard to only load PGP::Sign and
#    Signify at runtime when used, not use Linux runlevel as a test for
#    immutable capability, and not run Linux lsattr on character special
#    files or files on fuse, msdos, or other non-standard filesystems.
# Modified 20 September 2025 by Jim Lippard to use full references for
#    calls to PGP::Sign and add default Linux config.
# Modified 28 September 2025 by Jim Lippard to only run create_tree/fork
#    children on specified sets when -s is used, to count devpts file
#    system type as "nonstandard", and to ignore /dev/core in default
#    Linux config.
# Modified 4-5 November 2025 by Jim Lippard to replace mktemp calls with
#    File::Temp for non-OpenBSD systems and remove backtick/shell calls
#    using open pipes. Add tree name in "Specification created" message
#    since it may not be clear when using fork manager.
# Modified 2 December 2025 by Jim Lippard to delete a few more env
#    variables.
# Modified 7 December 2025 by Jim Lippard to use Cwd::abs_path on
#    link targets in FileAttr package and only load Parallel::ForkManager
#    if forking children.
# Modified 11 December 2025 by Jim Lippard to use File::Spec->rel2abs
#    when link target contains "../" and doesn't exist.
# Modified 4 January 2026 by Jim Lippard to remove & from subroutine calls,
#    add -V to just print version (in addition to -h).
# Modified 5-6 January 2026 by Jim Lippard to add privilege separation option
#    via -p option or "privsep:" field in config file. Add require_module
#    subroutine. (In preparation for adding privilege separation.)
# Modified 10 January 2026 by Jim Lippard to avoid use of cwd in use of
#    File::Spec->rel2abs.
# Modified 11 January 2026 by Jim Lippard to be more granular with pledge,
#    stop locking the top specs dir ($spec_dir_dir), and move spec specs
#    and changedfiles into specs and secondary.
# Modified 18 January 2026 by Jim Lippard to move verify_required_dirs out
#    of subroutines so it can occur before privilege separation, cleanup
#    some option checking, and add PrivSep package.
# Modified 24 January 2026 by Jim Lippard to add privileged parent code and
#    modify immutable flag handling to work with privsep; fighting with Claude
#    to properly update FileAttr for privilege separation without breaking anything.
#    (Currently on revision 50 of Claude's designed changes and still finding
#    errors and omissions.)
# Modified 25-28 January 2026 by Jim Lippard, through version 83 of Claude
#    design changes, some of which were really bad ideas that have been
#    discarded (like passing entire file contents of specs and changed files
#    through sockets instead of passing file handles).
# Modified 29 January 2026 by Jim Lippard to replace Storable-based IPC
#    protocol with JSON.
# Modified 31 January 2026 by Jim Lippard to fix race condition in FD passing for Linux
#    by modifying the protocol to force synchronization.
# Modified 1 February 2026 by Jim Lippard to add FD passing ACK timeout for Linux and
#    fix bugs in child changed file handling, removing unnecessary locking for the child
#    changed files.
# Modified 1 February 2026 by Jim Lippard to fix the actual underlying FD passing problem which was
#    improper assignment of worker sockets.
# Modified 4 February 2026 by Jim Lippard to properly handle nonprinting characters in file
#    and directory names with privilege separation. Add strict/warnings for
#    each package.
# Modified 7 February 2026 by Jim Lippard to correct references to $MAIN_PRIV_SOCK to use
#    $FileAttr::PRIV_IPC, remove warning if directory or file is missing in
#    request_stat as that is normal and expected. Make GPG signing work with
#    privsep despite lack of tty.
# Modified 14 February 2026 by Jim Lippard to not set PGP_or_GPG to "GPG1" when
#    using privsep with GPG2, as it then displays "GPG1" in multiple places it
#    shouldn't. We already had a redundant check, which we keep, before prompting
#    for a passphrase (which doesn't work with gpg-agent in privsep mode).
# Modified 27 February 2026 by Jim Lippard to remove tmppath pledge.
# Modified 13 April 2026 by Jim Lippard to count mtimestasis violations (lack
#    of change for some period of time) as changes so that they display even
#    if there are no other changes to report.
# Modified 16 April 2026 by Jim Lippard to warn about world-readable config
#    and warn about spec permissions when they are group or world-readable.
# Modified 1 May 2026 by Jim Lippard to wipe $pgp_passphrase from memory after use,
#    not follow symlinks for privileged file opens for writing (handle_open_request),
#    not follow symlinks for nonpriv file opens for writing (Spec and ChangedFile
#    packages, using new main::safe_open_for_write), and tighten up checks in
#    is_sigtree_managed_file (prevent directory traversal, be stricter on file
#    names). Prompted by Claude Security assessment (Opus 4.7).
# Modified 2 May 2026 by Jim Lippard to add interrupt handler for passphrase input
#    to restore tty echo.
# Modified 12 May 2026 by Jim Lippard to use correct location for $SYSCTL on
#    macOS (old OpenBSD location, see change above from 10 June 2004) and
#    parse sysctl output for securelevel correctly on macOS. Properly handle
#    legacy changed file moved to new location. Set descriptive process names
#    for child processes.
# Modified 15 May 2026 by Jim Lippard to shorten process names.
# Modified 17 May 2026 by Jim Lippard to move config permissions checks
#    into Config package to avoid TOCTOU races. Switched from -w to
#    "use warnings".
# Modified 1 July 2026 by Jim Lippard after Claude Opus 4.8 review:
#    privsep readdir key mismatch (entries vs entries_b64); missing "/" in the
#    host-spec existence check in verify_required_dirs; wrong-case {nlink} key
#    in FileAttr::compare; reset_changed_file using () instead of {} for hash
#    fields (TIME/USER kept, to preserve check history); dead $changed_file
#    vs $changedfile check in check_sets; removed dead request_write_file/
#    request_read_file; use eq/quotemeta instead of regex for tree-path
#    matching; fork-count off-by-one; tightened child_procs config validation;
#    stale recv_request comment. Also hardened priv and nonpriv reads against
#    symlink/TOCTOU swaps (O_NOFOLLOW, ELOOP/EMLINK detection, fstat dev/ino
#    verification) and added a refuse-to-write-through-symlink message.
# Modified 15 October 2026 by Claude Opus 5.5 at the direction of Jim
#    Lippard after review against the audit checklist (version 1.26):
#    call Signify::sign and Signify::verify with Signify.pm's named
#    arguments and require Signify.pm 1.4 (1.3 can report a successful
#    signing with a signify -n key as failed). Privileged parent:
#    is_allowed_path rejects ".." components, so the unprivileged process
#    can no longer have root open any file via "$tree/../.."; removed the
#    /tmp/sigtree.* exception from is_sigtree_managed_file (unused under
#    privsep), through which the unprivileged process could have root
#    run chflags on a symlink it placed in /tmp; chflags now runs with -h
#    so a symlink is never followed; signing and verification use the
#    parent's own method and keys, not the request's; the passphrase it
#    receives is overwritten after use. A failed signature (signify or
#    PGP) now stops initialize and update, and update signs a spec before
#    removing its tree from the changed file, so a wrong passphrase no
#    longer leaves specs with stale signatures and the changes forgotten.
#    initialize and update also sign a throwaway file right after the
#    passphrase prompt (in the privileged parent under privsep), so a
#    wrong passphrase stops them before any spec is changed.
#    initialize and check now treat a worker that died as failed (its
#    tree's changes are kept; check does not write a changed file with a
#    tree missing) and exit non-zero. chflags/chattr failures are
#    reported and fatal, including under privsep, where the request used
#    to report success; "Unable to reset" no longer exits 0. Securelevel
#    -1 is accepted and treated as 0; sysctl failures are reported.
#    update's "Failed to load spec ... skipping" now skips only that tree
#    (it ended the update with the spec dir unlocked). An absolute -d
#    outside the root dir now works under privsep (the privileged parent
#    refused the host spec, which is in the spec dir's parent) and its
#    spec dir is in the sigtree set (it had no set). An absolute
#    exception or exception-tree path is now a config error (it never
#    matched, and with an ignored set gave no warning), and an
#    exception-tree for the whole tree says to change the tree's sets
#    instead. unveil: the spec
#    dir's parent is unveiled when an absolute -d puts it outside the
#    root dir; dropped x where nothing is exec'd and /bin/sh for the
#    immutable commands (ls is run directly). Removed the Linux-only FD
#    ACK (reads are exact-length sysread) and bounded the descriptor wait
#    at 30 seconds instead; SIGPIPE is ignored around socket writes; a
#    lost or corrupt privsep response is fatal instead of read as
#    success. Worker temp changed files are marked by the caller rather
#    than by a /tmp/ path prefix, and their temp dir is removed even
#    after a worker died with its file half-written. Spec and changed
#    file writes check close. yes_or_no treats end of input as no; no passphrase at end of
#    input is an error. The passphrase is overwritten at the end of
#    initialize and update (the 1 May wipe applied only to an empty
#    string). require 5.010, which the code already needed.
# Modified 6 November 2026 by Claude Opus 5.5 at the direction of Jim
#    Lippard (version 1.27): a read error part way through hashing a file
#    (Digest::SHA's "Read failed", e.g. ETIMEDOUT for a macOS cloud-backed
#    file) is now reported with the file's path and the file is treated
#    like one that cannot be opened; it used to kill the worker, and in 1.26
#    the whole check then wrote no changed file. When a worker does fail,
#    check now writes the changed file with this run's results for the
#    other trees and the previous check's results for the failed tree, and
#    still exits non-zero. The dev/ino identity check between stat and
#    open never ran: the two values were passed concatenated ("." for ",").
#    A privileged stat that fails with ENOTDIR (a directory in the spec has
#    become a file) is no longer warned about, like ENOENT; the paths are
#    still reported as deleted.
# Modified 7 November 2026 by Claude Opus 5.5 at the direction of Jim
#    Lippard (version 1.28): speed. Every path's flags were read by running
#    ls (BSD, macOS) or lsattr (Linux, plus a stat for the filesystem
#    type) on that one path, so each path forked the whole process, and a
#    process holding a large spec forks slowly (most of the time of a
#    macOS check or update). Flags are now read in batches of up to 200
#    paths -- per directory in initialize and check, all changed paths at
#    once in update -- and not at all for a path whose set does not check
#    flags. A path a batch cannot account for is read on its own as
#    before. ChangedFile::add checked for a duplicate by scanning the
#    tree's whole list, so recording N changes took N*N/2 comparisons
#    (hours after a major OS upgrade); it now keeps a lookup hash, which
#    is not stored. New config fields primary-exception:,
#    secondary-exception:, primary-exception-tree: and
#    secondary-exception-tree:, which apply only to primary specs (any
#    run without -d secondary) or only to secondary specs, so a path can
#    be in a different set in each -- e.g. a log that must change daily,
#    in a CRIT-LOGS set for the secondary specs, ignored in the primary
#    specs because it does not exist in single-user mode. A path has
#    either a shared exception: line or per-mode lines, not both. The
#    other mode's lines are checked as usual (so errors show in either
#    mode) but not used, and do not warn about a missing path.
# Modified 8 November 2026 by Claude Opus 5.5 at the direction of Jim
#    Lippard (version 1.28a): under privsep on Linux, 1.28's batched
#    lsattr ran in the unprivileged process on every path, including
#    those it cannot open, and printed "lsattr: Permission denied While
#    reading flags on ..." for each (the flags recorded were right: such
#    a path was then read through the privileged parent). The batch now
#    leaves those paths to the privileged parent, as 1.27 did.
# Modified 8 November 2026 by Claude Opus 5.5 at the direction of Jim
#    Lippard (version 1.29): new verify_hosts command, for a server that
#    collects other hosts' sigtree databases. With its own config file
#    (default /etc/sigtree.hosts.conf), it reports for each host: the age
#    of its primary changed file, or that it has none; spec files changed
#    between the previous and current rsnapshot snapshots, and any that
#    match an older snapshot instead (an old signed spec put back); bad
#    or missing signify signatures, checked with a public key pinned in
#    the config; and, among hosts marked as peers, files under common
#    paths that differ from what most peers have, are missing, or exist on
#    one host only. A spec is loaded only after its signature verifies,
#    in a child running as _sigtree. Prints nothing when all is well.
# Modified 8 November 2026 by Claude Opus 5.5 at the direction of Jim
#    Lippard (version 1.30): the primary and secondary changed files are
#    no longer deleted when empty; check, initialize and update leave
#    them in place, so a changed file's mtime is the time of the last
#    check (verify_hosts relies on it) and an empty one means nothing is
#    pending. changes exits 0 if changes are pending in the specified
#    sets and 1 if none are (or there is no changed file), so cron can
#    run update only when needed; update with nothing to update says so
#    and exits 0. verify_hosts: the rollback check walks every snapshot
#    between the previous and current ones, so a spec put back within a
#    week-long window is caught; previous-age: N picks the newest snapshot
#    at least N days older than the current one; "verify_hosts host
#    [spec | /path]" shows on demand what changed in that host's specs,
#    or one spec, or one file, with a diff of its two versions when
#    backups of both are found by their digests (SHA-3, then SHA-2, of
#    the digest's size); host-written names, paths and file contents are
#    printed with control characters escaped (1.29 printed them raw).
#    Device nodes' device numbers are recorded, and compared by a new
#    keyword, rdev (not in the defaults: for a set covering device nodes,
#    such as a chroot's dev/); a spec from before 1.30 has
#    none, so nothing is compared until the tree is re-initialized. They
#    are shown as major,minor as the running OS encodes them (OpenBSD,
#    macOS and Linux differ). verify_hosts checks chroots ("chroot:"
#    blocks): no setuid or setgid files and no device nodes outside dev/;
#    in the mirrored directories, dev/ and etc/, everything owned by root
#    and not group or world writable (device nodes excepted); nothing
#    under an allow-only: directory that is not listed; each file under
#    a mirror: directory the same as the host's own copy at the same
#    path (digest, mode, owner, device number, link target), and none
#    without one unless in allow-extra:; and, in those system parts,
#    files that every host's copy of the chroot has, the same on each
#    (compare-except: for any that differ by design). "reference:" names
#    files on the host running verify_hosts that every host (or those in
#    reference-hosts:) must have the same; a host whose specs lack one is
#    reported, and the detail query for such a path diffs the host's
#    backed-up version against this host's copy.
#    In the detail query, a version whose signature cannot be checked
#    (a GPG signature from before the host moved to signify, say) is
#    reported, named as such, and the other specs are still shown.
# Modified 10 November 2026 by Claude Opus 5.5 at the direction of Jim
#    Lippard (version 1.31): in the verify_hosts detail query, when the
#    previous snapshot's copy of a spec cannot be verified (a GPG
#    signature from before the host moved to signify, say), its changes
#    are shown from the oldest later snapshot in the window whose copy
#    does verify, and the report says which; before, that spec was
#    skipped. The detail query no longer lists changes in mtime and ctime
#    (which specs record whatever the host's keywords) unless -v is
#    given, and counts the paths that changed only in those; -k names
#    the attributes to show instead, as sigtree keywords.
#    check now stores, for each changed attribute, the spec's value and
#    the value found, in the changed file (a changed file from before
#    1.31 has only the names, and is shown with names only). check's
#    closing summary and changes -v show the values, with digests
#    shortened; plain changes lists each path's changed attributes, or
#    that it was added or deleted. "changes spec" (a spec file's name,
#    such as etc or usr.local) and "changes /path" (a file, or the
#    pending paths at or beneath a directory) show the values in full,
#    or with -v in check's long form, and look at each path again: a
#    change since undone (the path as in the spec again, or an added
#    file removed or a deleted one restored) or a further change since
#    the check is reported. -k limits changes, its summary and these to
#    the attributes named. The display of a change is shared by check,
#    changes and verify_hosts (AttrDisplay package); modes are shown as
#    permission bits in four octal digits throughout, and file names and
#    values with control characters escaped. Fixed: after an update or
#    initialize of some trees, their paths stayed in the changed file's
#    per-set lists, so changes -v still listed them; and with -m,
#    a path left out of the summary put the following paths' changed
#    attribute names out of step.
#    -m now does what it was meant to: changes inside a macOS app are
#    counted per app ("Inside macOS apps": n changed, added, deleted) in
#    check's summary, changes -v and plain changes, instead of being
#    left out, which hid an app altogether when its bundle directory
#    had not itself changed; check -v no longer shows them one by one
#    (it did, while leaving out only the mtimestasis-only case); a tree
#    that is itself an app is handled the same way; changes /path for
#    an app or inside one lists them in full. Also fixed: check recorded
#    no check time for the spec dir, so changes died (exit 2) whenever
#    check had found the spec dir changed; and update stopped scanning
#    the changed file at the first tree to update, so a tree no longer
#    in the config was removed from it only if found before that.
#    check_file checked nothing but the spec dir: the file's tree was
#    dropped when trees were chosen by set (the path stood where the
#    sets go), and for a directory below a tree's root, the paths of
#    its entries left out that directory.
#    A check now replaces only the changed file's records for what it
#    covered: with -s, the trees in those sets; check_file, the path and
#    everything beneath it; check_specs, only the spec dir (which every
#    check covers). Pending changes elsewhere are carried over from the
#    previous check, with their values and check times (a tree whose
#    worker fails is carried over the same way). Before, every check
#    replaced all of them, so a check of some sets, or check_file, lost
#    the other trees' changes before they had been reviewed or updated.
# Modified 11 November 2026 by Claude Opus 5.5 at the direction of Jim
#    Lippard (version 1.32), after a review of 1.31 by another session:
#    check_file makes its path canonical as specs record paths (no "//",
#    "/./" or trailing "/", and ".." resolved, refused after a symlink);
#    since 1.31 made check_file work, "check_file dir/" or "../file"
#    recorded every file under a name like "dir//file" that update then
#    put in the spec for good. File names and privileged-parent errors are
#    printed with control characters escaped in update's output (including
#    the "There are no longer changes" warning), the spec dir's path list,
#    the extraneous-file list, and the per-file warnings while hashing, as
#    check -v and the summary already were. changes exits 2 on every error,
#    including a bad option or -k keyword (the handler is now installed
#    before options are checked), and an option given after the command
#    ("changes -v") is refused as such before anything else. On OpenBSD,
#    chflags and ls are unveiled whatever immutable-specs says: flags are
#    read whenever a set has the flags keyword (a default), and with
#    immutable-specs: no every path's flags were recorded as undefined.
#    Under privsep, the spec dir's extraneous files are listed before the
#    drop to _sigtree; check -v said there were none. verify_hosts checks
#    that each spec holds the tree its file name is for (a validly signed
#    spec copied over another tree's name), reports a mismatch and leaves
#    that spec out.
# Modified 12 November 2026 by Claude Opus 5.5 at the direction of Jim
#    Lippard (version 1.32a): on OpenBSD, 1.32 tested whether chflags and
#    ls exist after the first unveil() call, when such a test reports any
#    path not yet unveiled as missing, so neither was unveiled and every
#    path's flags were recorded as undefined (a flags change on every
#    path in every check). All the file tests in the unveil block are now
#    made before the first unveil, which also corrects the test of an
#    absolute -d spec dir outside the root dir (its parent was unveiled
#    instead of the dir itself).
# Modified 14 November 2026 by Claude Opus 5.5 at the direction of Jim
#    Lippard (version 1.32b): update and initialize stop, before the
#    passphrase prompt, when the specs are locked with schg and the
#    securelevel is above 0. The test was there, but as the last branch of
#    an if/elsif chain that reached it only when the host spec did not
#    exist, so update asked for the passphrase and then failed at the first
#    chflags ("Operation not permitted").
# Modified 14 November 2026 by Claude Opus 5.5 at the direction of Jim
#    Lippard (version 1.32c): verify_hosts's comparison of a chroot across
#    its hosts leaves out a file whose system counterpart is in except:
#    (libc, ld.so and the other files relinked at boot): each host's copy
#    is a copy of its own relinked file, so they always differed. Each
#    copy is still compared with its own host's system file.

### Required packages.

# sigtree.pl requires the following in order to work:
# * Perl 5.10 or later.
# * Standard Perl modules File::Basename, File::Temp, Getopt::Std,
#   Storable, and Sys::Hostname.
# * Standard Perl module Cwd used in FileAttr and for check_file.
#   (OpenBSD::MkTemp used in place of File::Temp on OpenBSD systems.)
#   (File::Temp is a very large module (3000+ lines) and only used
#   if PGP/GPG signing is done or children are forked.)
# * CPAN module Digest::SHA
# * CPAN module Parallel::ForkManager (if forking children)
# * If PGP/GPG/signify signing is used (recommended):
#   * PGP 5 or later or GPG.
#   * CPAN module PGP::Sign.
#   * Or: /usr/bin/signify (signify-openbsd for Linux)
#   * /bin/stty (for PGP or GPG 1, without gpg-agent)
#   * /usr/bin/tty (for GPG 2, with gpg-agent)
#   * Signify.pm 1.4 or later, wrapper for signify
# * If immutable flags are used (recommended for BSD):
#   BSD:
#   * /usr/bin/chflags (schg/noschg or uchg/nouchg)
#   * /sbin/sysctl kern.securelevel (/usr/sbin/sysctl on macOS)
#   Linux:
#   * /usr/bin/chattr (+i/-i)
#   * /usr/bin/lsattr
#   * /usr/bin/stat
# If privilege separation is used:
#   * JSON::MaybeXS or JSON::PP for IPC protocol
#   * IO::Handle, IO::Select, IO::Socket
#   * IO::FDPass
#   * Privileges::Drop
#   * MIME::Base64
# Note that each of these dependencies is potentially a route that
# could be exploited to subvert this program's intended function.
#
# It is recommended that you keep a copy of this code and your
# specifications on a separate machine and periodically copy them
# over and run checks.  For the ultra-paranoid, you can periodically
# re-install known clean copies of Perl and the Perl module
# Digest::SHA and PGP::Sign before a check, or (perhaps easier),
# copy your spec dir to a known clean system and do a check_specs
# on them (use a known clean $spec_dir/$HOSTNAME.spec file).

require 5.010; # feature 'state' and the // operator
use strict;
use warnings;
use feature 'state';
use Digest::SHA;
use Digest::SHA3;
use Errno qw( ELOOP EMLINK ); # for use in handle_read_request
use Fcntl qw( :DEFAULT O_NOFOLLOW :flock ); # for use with sysopen in handle_open_request and for safe_open_request
use File::Basename;
# File::Temp is much larger than OpenBSD::MkTemp.
use if $^O ne "openbsd", "File::Temp", qw ( :mktemp tempfile );
use Getopt::Std;
# for privsep:
#use IO::Handle;
#use IO::Select;
use IO::Socket;
#use IO::Socket::UNIX; # not used unless reportnew subs are borrowed
use MIME::Base64 qw( encode_base64 decode_base64 );
use Sys::Hostname;
use if $^O eq "openbsd", "OpenBSD::MkTemp", qw( mkstemp mkdtemp );
use if $^O eq "openbsd", "OpenBSD::Pledge";
use if $^O eq "openbsd", "OpenBSD::Unveil";

### Sanitize environment.
BEGIN {
    $ENV{PATH} = '/usr/bin:/bin';
    delete @ENV{qw(IFS CDPATH ENV BASH_ENV PERL5LIB LD_PRELOAD LD_LIBRARY_PATH)};
}

### Global constants.

use vars qw( $SECURELEVEL );

$SECURELEVEL = 0;

my $BINSH = '/bin/sh'; # needed for unveil only
my $CHATTR = '/usr/bin/chattr';
my $LSATTR = '/usr/bin/lsattr';
my $LSATTR_FLAGS_OPT = '-d';
my $CHFLAGS = '/usr/bin/chflags';
my $LIST_FLAGS_CMD = '/bin/ls';
my $LIST_FLAGS_OPT = '-lod';
my $MAC_LIST_FLAGS_OPT = '-lOd';
my $SIGNIFY = '/usr/bin/signify';
my $STAT = '/usr/bin/stat';
my $STTY = '/bin/stty';
my $SYSCTL = '/sbin/sysctl';
$SYSCTL = '/usr/sbin/sysctl' if ($^O eq 'darwin');
my $TTY = '/usr/bin/tty';
my $BSD_SYS_IMMUTABLE_FLAG = 'schg';
my $BSD_USER_IMMUTABLE_FLAG = 'uchg';
my $LINUX_IMMUTABLE_FLAG = '+i';
my $LINUX_IMMUTABLE_FLAG_OFF = '-i';

my $VERSION = 'sigtree 1.32c of 14 November 2026';

# Now set in the config file, crypto_sigs field.
my $PGP_or_GPG = 'GPG'; # Set to PGP if you want to use PGP, GPG1 to use GPG 1, GPG to use GPG 2, signify to use signify.
my $ROOT_PGP_PATH = '/root/.pgp';
my $ROOT_GPG_PATH = '/root/.gnupg';
my $PGP_COMMAND = '/usr/local/bin/pgp';
my $GPG_COMMAND = '/usr/local/bin/gpg';
my $GPG_NOAGENT = '/usr/local/bin/gpg-noagent'; # Wrapper for batch-mode GPG (privsep, no tty in privileged process)
my $SIGTREE_SIGNIFY_PUBKEY = '/etc/signify/sigtree.pub';
my $SIGTREE_SIGNIFY_SECKEY = '/etc/signify/sigtree.sec';
my $VERIFY_HOSTS_CONFIG = 'sigtree.hosts.conf'; # in $SYSCONF_DIR, for verify_hosts

my $MAX_CHILD_PROCS = 5;
my $DEFAULT_CHILD_PROCS = 4;

my $MACOS_APP_CONTENTS = '\.app\/';
my $MACOS_APP = '\.app$';

my $OSNAME = $^O;

if ($OSNAME eq 'darwin') {
    $LIST_FLAGS_OPT = $MAC_LIST_FLAGS_OPT;
}

my $HOSTNAME = hostname() || die "Hostname is undefined.\n";
my $DOMAIN = '';
($HOSTNAME, $DOMAIN) = split (/\./, $HOSTNAME, 2);

my $USERNAME = getpwuid($<);

my $ROOT_DIR = '/var/db/sigtree';
my $SYSCONF_DIR = '/etc';

# Pledge promises.
# - rpath: Read filesystem paths
# - wpath: Write to files
# - cpath: Create new files
# - fattr: Get/set file attributes (immutable flags)
# - exec: Execute external programs (GPG, chflags, etc.)
# - proc: Process control (fork, waitpid)
# - unveil: Set filesystem restrictions
# - flock: File locking
# - sendfd: send file descriptor
# - recvfd: receive file descriptor
# - id: setuid/setgid
# - prot_exec: required to drop privs with Privileges::Drop
my @READONLY_PROMISES = ('rpath');
my @READWRITE_PROMISES = ('wpath', 'cpath');
my @CHANGE_ATTR_PROMISES = ('fattr');
my @EXEC_PROMISES = ('exec', 'proc');
my @FLOCK_PROMISE = ('flock');
my @UNVEIL_PROMISE = ('unveil');
my @PRIVSEP_PRIV_PROMISES = ('chown', 'sendfd');
my @PRIVSEP_NONPRIV_PROMISES = ('recvfd');
my @PRIVSEP_DROPPRIV_PROMISES = ('id', 'prot_exec');

# Privsep global (not really constants).
my @WORKER_SOCKETS; # Privileged parent array of child sockets.
my $PRIVILEGED_PARENT_PID; # PID of privileged parent.
our $MAIN_PRIV_SOCK; # Main socket to privileged parent from unprivileged process.
my @ALLOWED_TREES; # List of trees privileged parent can access.
our $use_privsep;  # Use privilege separation.
our @EXISTING_SPECS; # Collected before privs dropped to replace !-e tests.
our @EXTRANEOUS_SPECS; # Likewise, extraneous files in the spec dir (privsep).

# Return error codes for valid_setlist.
my $SET_NAME_INVALID = 1;
my $SET_UNDEFINED = 2;
my $SET_REDUNDANT = 3;
my $SET_INCLUDES_UNINITIALIZED = 4;

# Commands.
my $INITIALIZE = 1;
my $CHECK = 2;
my $UPDATE = 3;

my $SUBTREE = 0;
my $TREE_ROOT = 1;

my $ALL = 0;
my $SPECS_ONLY = 1;
my $SUBTREE_ONLY = 2;

# Immutable option.
my $IMMUTABLE_ON = 1;
my $IMMUTABLE_OFF = 0;

# Digest options.
my $SHA2_DIGEST = 2;
my $SHA3_DIGEST = 3;
my $NO_SHA2_DIGEST = 0;
my $SHA3_224 = 224;
my $SHA2_256 = 256;
my $SHA3_256 = 256;
my $SHA2_384 = 384;
my $SHA3_384 = 384;
my $SHA2_512 = 512;
my $SHA3_512 = 512;

### Main program variables.

my (%opts,         # Command line options.
    $command,      # Command to execute.
    $file,         # File to check (for check_file).
    $config_file,  # Config file to use.
    $set,          # List of sets to use.
    @sets,         # List of sets being processed.
    $arg_no,       # Used for returning error message on set list validation.
    $error,        # Ditto.
    $something_to_do, # Are any trees members of specified sets?
    $priv_flag,    # if running privileged.
    $nonpriv_flag # if running nonprivileged.
    );

our ($root_dir,     # Root dir to use.
     $spec_dir_dir, # Directory containing specifications directories.
     $spec_dir,     # Specifications dir to use.
     $spec_spec,    # Specification for specifications dir.
     $secondary_specs, # Are we using secondary specs? If so, no PGP/immutable.
     $changed_file, # Changed specifications file to use.
     $config,       # Config file object.
     $debug_flag,   # For debugging messages.
     $fork_children,# number of children to fork.
     $no_macos_app_contents, # don't show stuff that is inside an app directory.
     $changes_query, # "changes spec" or "changes /path": the spec or path.
     $use_pgp,      # If PGP, GPG, or signify should be used.
     $use_signify,  # If signify should be used.
     $signify_pubkey, # signify public key file.
     $signify_seckey, # signify private key file.
     $sigtree_uid,  # uid of _sigtree user.
     $sigtree_gid,  # gid of _sigtree group.
     $use_immutable,# If system immutable flags should be used.
     $immutable_flag,# For BSD, which type of immutability to use.
     $verbose,      # If we should be verbose.
    );

### Main program.

# Set umask.
umask 077;

# changes exits 0 if changes are pending and 1 if none are, so an error
# must not exit 1. die's exit status is $! when that is set (it can be 1),
# so for changes an error outside an eval exits 2. Installed before the
# options are checked (1.32), since a bad option is an error too; $command
# is set as soon as it is known (if getopts fails, from what it left).
$SIG{__DIE__} = sub {
    # Inside an eval, or while code is being compiled (a module's
    # eval { require ... } at load time): let it be handled as usual.
    return if (!defined ($^S) || $^S);
    return unless (defined ($command) && $command eq 'changes');
    print STDERR $_[0];
    exit (2);
};

# Get/set options.
unless (getopts ('r:c:s:d:f:k:vhmpVD', \%opts)) {
    $command = $ARGV[0];
    die "sigtree.pl -h for help.\nUsage: sigtree.pl [options] command\n";
}
$command = $ARGV[0] if (@ARGV);

# Debugging.
$debug_flag = $opts{'D'} || 0;

# -V must be alone.
if ($opts{'V'}) {
    die "-V is mutually exclusive with other options.\n" if (keys (%opts) > 1);
    die "-V is mutually exclusive with any commands.\n" if ($#ARGV >= 0);
    print "$VERSION\n";
    exit;
}

$root_dir = $opts{'r'} || $ROOT_DIR;
$spec_spec = $HOSTNAME . '.spec';
$config_file = $opts{'c'} || $SYSCONF_DIR . '/' . $HOSTNAME . '.sigtree.conf';
$config_file = $SYSCONF_DIR . '/' . $config_file if ($config_file !~ /^\.\/|^\//);
$set = $opts{'s'} || 0;

# if -m, then don't display app dir contents from changes/show_changes/show_change_details.
$no_macos_app_contents = $opts{'m'} || 0;

# check -f for integer, but do check on quantity after parsing config.
if ($opts{'f'}) {
    die "-f option must be an integer number of child processes.\n" if ($opts{'f'} !~ /^\d+$/);
    die "-f option must be 0 or >= 2 child processes.\n" if ($opts{'f'} == 1);
}

if ($opts{'d'}) {
    if (substr ($opts{'d'}, 0, 1) eq '/') {
	$spec_dir = $opts{'d'};
	$spec_dir_dir = File::Basename::dirname ($spec_dir);
    }
    else {
	if ($opts{'d'} eq 'secondary') {
	    $secondary_specs = 1;
	    $spec_dir = $root_dir . '/' . $opts{'d'} . '/' . $HOSTNAME;
	    $spec_dir_dir = $root_dir . '/' . $opts{'d'};
	    $spec_spec = $HOSTNAME . '.specsec';
	}
	else {
	    $spec_dir = $root_dir . '/' . $opts{'d'};
	    $spec_dir_dir = $root_dir;
	}
    }
}
else {
    $spec_dir = $root_dir . '/specs/' . $HOSTNAME;
    $spec_dir_dir = $root_dir . '/specs';
}
if ($secondary_specs) {
    $changed_file = $spec_dir_dir . '/' . $HOSTNAME . '.changedsec';
}
else {
    $changed_file = $spec_dir_dir . '/' . $HOSTNAME . '.changed';
}

$verbose = $opts{'v'} || 0;

if ($opts{'h'}) {
    print "$VERSION\n";
    print "Usage: sigtree.pl [options] command\n";
    print "Options:\n";
    print "-r root_dir\n";
    print "-c config_file\n";
    print "-d spec_dir (absolute path or relative to root_dir)\n";
    print "-s set list (CSV)\n";
    print "-f num_child_procs\n";
    print "-m don't show macOS app dir content changes\n";
    print "-p use privilege separation\n";
    print "-v verbose\n";
    print "-k keyword list (CSV; changes and the verify_hosts detail query: the attributes to show)\n";
    print "-V show version (must be standalone option with no command)\n";
    print "-h help and show version\n";
    print "Commands:\n";
    print "initialize: Initialize specifications for a set of trees.\n";
    print "initialize_specs: Initialize specification for the specification dir.\n";
    print "changes: Show non-updated or reinitialized changes found by check.\n";
    print "   changes spec | /path: show the pending changes in that spec's tree, or at or\n";
    print "   beneath that path, with values, and any since undone or changed again.\n";
    print "check: Check specifications for a set of trees.\n";
    print "check_file: Check an individual file against a specification.\n";
    print "   (The file name is specified on the command line after \"check_file\".)\n";
    print "check_specs: Check specification for the specification dir.\n";
    print "update: Update specifications with changes found by check.\n";
    print "verify_hosts: Check copies of other hosts' sigtree databases (on a central server).\n";
    print "   (-c names its own config file, default $SYSCONF_DIR/$VERIFY_HOSTS_CONFIG.)\n";
    print "   verify_hosts host [spec | /path]: show what changed in that host's specs\n";
    print "   (or one spec, or one file, with a diff from the backups if both versions are there).\n";
    exit;
}

if ($#ARGV >= 0) {
    $command = $ARGV[0];
    $file = $ARGV[1] if ($#ARGV > 0);
}

if (!defined ($command) || ($command eq 'check_file' && $#ARGV != 1) ||
    ($command eq 'verify_hosts' && $#ARGV > 2) ||
    ($command eq 'changes' && $#ARGV > 1) ||
    ($command ne 'check_file' && $command ne 'verify_hosts' && $command ne 'changes' &&
     $#ARGV != 0)) {
    die "sigtree.pl -h for help.\nUsage: sigtree.pl [options] command\n";
}

# Additional option limits, and complain if not a known command.
# No -s or -f.
if ($command eq 'initialize_specs' ||
    $command eq 'check_file' ||
    $command eq 'check_specs') {
    die "The -s option cannot be used with $command.\n" if ($opts{'s'});
    die "The -f option cannot be used with $command.\n" if ($opts{'f'});
}
# No -f.
elsif ($command eq 'changes' ||
       $command eq 'update') {
    die "The -f option cannot be used with $command.\n" if ($opts{'f'});
}
elsif ($command eq 'verify_hosts') {
    # Its own config (-c), and none of the per-host options.
    foreach my $opt ('r', 's', 'd', 'f', 'm', 'p') {
	die "The -$opt option cannot be used with verify_hosts.\n" if ($opts{$opt});
    }
    die "The -k option is for the verify_hosts detail query (verify_hosts host ...).\n"
	if (defined ($opts{'k'}) && $#ARGV < 1);
}
elsif ($command ne 'initialize' &&
       $command ne 'check') {
    die "Unknown command \"$command\".\n"
}
die "The -k option can only be used with changes and verify_hosts.\n"
    if (defined ($opts{'k'}) && $command ne 'verify_hosts' && $command ne 'changes');
# changes -k: show only these attributes.
AttrDisplay::set_filter (AttrDisplay::keyword_attrs ($opts{'k'}))
    if (defined ($opts{'k'}) && $command eq 'changes');
# getopts stops at the command, so "changes -v" passes -v on as an operand.
die "Options go before the command: sigtree.pl " . AttrDisplay::esc ($ARGV[1]) . " changes\n"
    if ($command eq 'changes' && $#ARGV == 1 && $ARGV[1] =~ /^-/);
# changes spec or changes /path: the spec name or path asked about. The
# paths are looked at again, which for flags runs ls or lsattr.
$changes_query = $ARGV[1] if ($command eq 'changes' && $#ARGV == 1);


# verify_hosts reads other hosts' copied databases, not this host's
# sigtree config, so it runs before that config is read.
if ($command eq 'verify_hosts') {
    my $hosts_config = $opts{'c'} ? $config_file : $SYSCONF_DIR . '/' . $VERIFY_HOSTS_CONFIG;
    exit (VerifyHosts::run ($hosts_config, $verbose, $OSNAME, $opts{'k'}, @ARGV[1 .. $#ARGV]));
}

$config = new Config ($config_file);

if ($set) {
    ($arg_no, $error, @sets) = $config->valid_setlist ($set);
    if ($error == $SET_NAME_INVALID) {
	die "Invalid set name \"$sets[$arg_no]\" given with -s option.\n";
    }
    elsif ($error == $SET_UNDEFINED) {
	die "Undefined set name \"$sets[$arg_no]\" given with -s option.\n";
    }
    elsif ($error == $SET_REDUNDANT) {
	die "Second set \"$sets[$arg_no]\" found in -s option.\n";
    }
    elsif ($error == $SET_INCLUDES_UNINITIALIZED) {
	# Only valid for "initialize" command.
	if ($command ne 'initialize') {
	    die "The set name \"$sets[$arg_no]\" given with -s option can only be used with the \"initialize\" command.\n";
	}
	# Add 'new' set to all trees without specs.
	add_new_set_to_uninitialized_trees ($spec_dir);
    }
    $something_to_do = 0;
    foreach $set (@sets) {
	if ($config->set_has_trees ($set)) {
	    $something_to_do = 1;
	}
	else {
	    print "Warning: Set \"$set\" has no trees as members. (It appears to be a\n   primary set rather than a tree-grouping set.)\n";
	}
    }
    if (!$something_to_do) {
	die "No sets specified have any trees as members.\n";
    }
}
else {
    # If no set is specified, use them all.
    @sets = $config->all_sets;
}

# Handle -f option. Placed here to allow a config option for
# max and default child counts vs. the hard coded ones.
if ($opts{'f'}) {
    die "-f option is greater than max number of child processes ($config->{MAX_CHILD_PROCS}).\n" if ($opts{'f'} > $config->{MAX_CHILD_PROCS});
}

$fork_children = $config->{DEFAULT_CHILD_PROCS};
$fork_children = $opts{'f'} if (defined ($opts{'f'}));

# Load Parallel::ForkManager if required.
if ($fork_children) {
    require_module ('Parallel::ForkManager') or
	die "Could not require Parallel::ForkManager. $@\n";
}

# Handle crypto_sigs options.
# If configuration doesn't have a crypto_sigs field, rely on PGPKEYID
# as before. Default to GPG2 (GPG).
if (!$config->{CRYPTO_SIGS}) {
    $use_pgp = $config->{PGPKEYID};
    $use_signify = ($use_pgp eq 'signify');
    if ($use_signify) {
	$PGP_or_GPG = 'signify';
    }
    else {
	$PGP_or_GPG = 'GPG';
    }
}
elsif ($config->{CRYPTO_SIGS} ne 'none') {
    $PGP_or_GPG = $config->{CRYPTO_SIGS};
    $use_pgp = 1;
    $use_signify = 1 if ($PGP_or_GPG eq 'signify');
    if (($PGP_or_GPG ne 'signify' && $config->{PGPKEYID} eq 'signify') ||
	($PGP_or_GPG eq 'signify' && ($config->{PGPKEYID} && $config->{PGPKEYID} ne 'signify'))) {
	die "Inconsistent crypto_sigs and pgpkeyid options in config file.\n";
    }
}
# Load required modules.
# Signify. ($use_pgp is also nonzero)
if ($use_signify) {
    require_module ('Signify') or
	die "Could not require Signify. $@\n";
    # The named-argument calls below need Signify.pm 1.3 or later (an
    # older module would take the hash reference as the passphrase or the
    # public key path), and 1.4 or later because 1.3 can report a
    # successful signing as failed with a key made with signify -n, which
    # sigtree now treats as fatal.
    eval { Signify->VERSION ('1.4'); 1 } or
	die "Signify.pm " . (Signify->VERSION // 'without a version') .
	    " is too old, 1.4 or later is required.\n";
}
# GPG or PGP.
elsif ($use_pgp) {
    require_module ('PGP::Sign') or
	die "Could not require PGP::Sign. $@\n";
}

# Handle immutability options.
$use_immutable = ($config->{IMMUTABLE_SPECS} ne 'no');
if ($use_immutable) {
    if ($config->{IMMUTABLE_SPECS} eq $BSD_SYS_IMMUTABLE_FLAG ||
	$config->{IMMUTABLE_SPECS} eq $BSD_USER_IMMUTABLE_FLAG) {
	$immutable_flag = $config->{IMMUTABLE_SPECS};
	if (!-e $CHFLAGS) {
	    die "Config file specified 'immutable-specs: $config->{IMMUTABLE_SPECS}' (BSD option), but does not appear to support them.\n";
	}
    }
    elsif (-e $CHATTR) {
	$immutable_flag = $LINUX_IMMUTABLE_FLAG;
    }
    else {
	$immutable_flag = $BSD_SYS_IMMUTABLE_FLAG;
    }
}

# Don't use PGP or immutable flags if using secondary specs, unless
# BSD's $BSD_USER_IMMUTABLE_FLAG is available.  (Using $BSD_USER_IMMUTABLE_FLAG
# is a possibility for the changed file, as well, now, but has not yet
# been implemented. If implemented, then the check functions will
# require the 'fattr' promise to be pledged.)
if ($secondary_specs) {
    $use_pgp = 0;
    if ($use_immutable && ($immutable_flag eq $BSD_SYS_IMMUTABLE_FLAG ||
			   $immutable_flag eq $BSD_USER_IMMUTABLE_FLAG)) {
	$immutable_flag = $BSD_USER_IMMUTABLE_FLAG;
    }
    else {
	$use_immutable = 0;
    }
}

if ($use_immutable) {
    if (-e $CHFLAGS) { # BSD
	open (my $outfh, '-|', $SYSCTL, 'kern.securelevel') or
	    die "Could not run $SYSCTL kern.securelevel: $!\n";
	$SECURELEVEL = <$outfh>;
	close ($outfh);
	if ($? != 0) {
	    die "$SYSCTL kern.securelevel failed (" .
		(($? & 127) ? 'killed by signal ' . ($? & 127) : 'exit ' . ($? >> 8)) . ").\n";
	}
	$SECURELEVEL //= '';
	chomp ($SECURELEVEL);
	$SECURELEVEL =~ s/^.*=\s*// if ($^O ne 'darwin');
	$SECURELEVEL =~ s/^.*:\s*// if ($^O eq 'darwin');
	# Securelevel is -1 (permanently insecure), 0, 1 or 2.
	if ($SECURELEVEL !~ /^-?\d+\z/) {
	    die "Could not parse securelevel from $SYSCTL kern.securelevel (\"$SECURELEVEL\").\n";
	}
    }
    elsif (-e $CHATTR) { # Linux
	# Immutable flags are equivalent to BSD uchg and there is no system
	# securelevel to consider.
	$SECURELEVEL = 0;
    }
    else {
	    die "Immutable file flags do not appear to be supported by your operating system.\n";
    }
}

if ($use_pgp) {
    if ($PGP_or_GPG eq 'PGP') {
	$PGP::Sign::PGPPATH = $config->{PGPKEYRING} || $ROOT_PGP_PATH;
	$use_signify = 0;
    }
    elsif ($PGP_or_GPG eq 'GPG') {
	$PGP::Sign::PGPPATH = $config->{PGPKEYRING} || $ROOT_GPG_PATH;
	$use_signify = 0;
    }
    elsif ($PGP_or_GPG eq 'signify') {
	$use_signify = 1;
	$signify_pubkey = $config->{SIGNIFY_PUBKEY} || $SIGTREE_SIGNIFY_PUBKEY;
	$signify_seckey = $config->{SIGNIFY_SECKEY} || $SIGTREE_SIGNIFY_SECKEY;
    }
    else {
	die "PGP_or_GPG is set to something other than PGP or GPG.\n";
    }
}

# Privilege separation part 1: verify that it can be done and
# load required modules, but don't fork until after pledge/unveil.
$use_privsep = $opts{'p'} || $config->{PRIVSEP} eq 'yes';
if ($use_privsep) {
    # verify that it's possible
    $sigtree_uid = getpwnam ('_sigtree');
    $sigtree_gid = getgrnam ('_sigtree');
    if ($USERNAME ne 'root' || !defined ($sigtree_uid) || !defined ($sigtree_gid)) {
	die "Cannot use privilege separation unless run as root and _sigtree user and group exist.\n";
    }
    # load required modules
    require_module ('IO::Handle')
	or die "Could not require IO::Handle. $@\n";
    require_module ('IO::Select')
	or die "Could not require IO::Select. $@\n";
    require_module ('IO::FDPass')
        or die "Could not require IO::FDPass. $@\n";
    require_module ('Privileges::Drop')
	or die "Could not require Privileges::Drop. $@\n";
}

# If OpenBSD, use pledge and unveil.
# This is occurring after config parsing but before all argument and
# file validation, so it's not quite as narrowly specified as it could
# be, but if we did it later it would need to be a subroutine called
# before or by initialize_sets, check_sets, update_sets, and show_changes,
# and could be more narrowly tailored for each based on need to access
# all or a subset of trees or just what's in the sigtree root dir.
if ($OSNAME eq 'openbsd') {
    # All the initial promises.
    my @promises = (@READONLY_PROMISES, @READWRITE_PROMISES,
		    @CHANGE_ATTR_PROMISES, @EXEC_PROMISES,
		    @FLOCK_PROMISE, @UNVEIL_PROMISE);
    push (@promises, @PRIVSEP_PRIV_PROMISES, @PRIVSEP_NONPRIV_PROMISES,
	  @PRIVSEP_DROPPRIV_PROMISES) if ($use_privsep);
    # stdio is automatically included
    pledge (@promises) || die "Cannot pledge initial promises. $!\n";

    # Need rwc for sigtree files. x is checked only for a path given to
    # exec, and nothing is run from these directories. Walking through a
    # directory needs no unveil permission on it. Unveiling a path that
    # doesn't exist yet fails, so unveil its parent instead.
    # From the first unveil() call on, a file test on a path not yet
    # unveiled says it does not exist, so every test is made first. (1.32
    # tested chflags and ls after unveiling the root dir, so neither was
    # unveiled and every path's flags were recorded as undefined.)
    my %exists = map { ($_ => (-e $_ ? 1 : 0)) } ($root_dir, $spec_dir_dir, $CHFLAGS, $LIST_FLAGS_CMD);
    foreach my $dir ($root_dir, $spec_dir_dir) {
	# An absolute -d spec dir may lie outside $root_dir.
	next if ($dir ne $root_dir && $dir =~ m{^\Q$root_dir\E(?:/|\z)});
	if ($exists{$dir}) {
	    unveil ($dir, 'rwc');
	}
	else {
	    unveil (File::Basename::dirname ($dir), 'rwc');
	}
    }

    # Need x to run the flag commands; r because they are file-tested.
    # (ls is run directly, not through /bin/sh.)
    # $SYSCTL absent because it's already been run.
    # Before 1.32 only with immutable flags in use, but flags are read
    # with ls whenever a set has the flags keyword (a default), and the
    # flag code tests that chflags exists first: without these, every
    # path's flags were recorded as undefined.
    unveil ($CHFLAGS, 'rx') if ($exists{$CHFLAGS});
    unveil ($LIST_FLAGS_CMD, 'rx') if ($exists{$LIST_FLAGS_CMD});
    # Need x for crypto sign/verify and keys.
    if ($use_pgp) {
	if ($use_signify) {
	    unveil ($SIGNIFY, 'rx');
	    unveil ($signify_pubkey, 'r');
	    unveil ($signify_seckey, 'r');
	}
	else {
	    unveil ($PGP::Sign::PGPPATH, 'r');
	    if ($use_privsep) {
		# gpg-noagent is a #! script, so its interpreter is
		# exec-checked under unveil too.
		unveil ($BINSH, 'rx');
		unveil ($GPG_NOAGENT, 'rx');
	    }
	    if ($PGP_or_GPG eq 'PGP') {
		unveil ($ROOT_PGP_PATH, 'rw');
		unveil ($PGP_COMMAND, 'rx');
	    }
	    else {
		unveil ($ROOT_GPG_PATH, 'rw');
		unveil ($GPG_COMMAND, 'rx');
	    }
	}

	# Need x for passphrase collection.
	unveil ($STTY, 'rx');
	unveil ($TTY, 'rx');
    }
    # Need /tmp access (worker temp files, GPG2 passphrase temp file).
    unveil ('/tmp', 'rwc');

    # Need r for all trees, and there could be symlinks from a tree
    # to a non-tree, so we just unveil /.
    unveil ('/', 'r');

    # Lock unveil.
    unveil ();
}

# Some additional options checking, and now verify (and potentially create)
# required directories before privilege separation. 'changes' will abort if
# there's no changed file and doesn't do this check.
if ($command eq 'initialize' ||
    $command eq 'initialize_specs') {
    verify_required_dirs ($INITIALIZE);

    # Remove any extraneous files from the specification directory.
    print "Removing extraneous files from specification dir.\n" if ($verbose);
    remove_extraneous_files ($config, $spec_dir_dir, $spec_dir, $verbose, $use_immutable);
}
elsif ($command eq 'check' ||
       $command eq 'check_file' ||
       $command eq 'check_specs') {
    verify_required_dirs ($CHECK);

    # Check existence of file with check_file. But don't abort, as if
    # it previously existed we'll report that in the check.
    if ($command eq 'check_file') {
	if ($file !~ m{^/}) {
	    require Cwd;
	    $file = Cwd::cwd () . '/' . $file;
	}
	$file = canonical_check_path ($file);
	print "File does not exist. " . AttrDisplay::esc ($file) . "\n" if (!-e $file);
    }
}
elsif ($command eq 'update') {
    verify_required_dirs ($UPDATE);
}

# Assemble list of existing specs prior to dropping privileges since file
# test operators won't work with privilege separation.
# Doing this AFTER any required dirs might have been created.
if ($use_privsep) {
    @EXISTING_SPECS = _identify_extraneous_files ($config, $spec_dir, 1);
    # And the extraneous ones, for check: after the drop to _sigtree the
    # 0700 spec dir cannot be read, and before 1.32 check -v then said
    # there were none.
    @EXTRANEOUS_SPECS = _identify_extraneous_files ($config, $spec_dir);
    push (@EXISTING_SPECS, $changed_file) if (-e $changed_file);
}

# Set $fork_children = 0 for commands that don't use it.
$fork_children = 0 if ($command ne 'initialize' && $command ne 'check');

# Privilege separation, part 2.
if ($use_privsep) {
    # Fork priv/nonpriv and re-do pledges accordingly.

    # Build list of allowed trees for privileged parent.
    @ALLOWED_TREES = $config->all_trees();
    push (@ALLOWED_TREES, $spec_dir) if $spec_dir;
    push (@ALLOWED_TREES, $root_dir) if $root_dir;

    # Set up main privileged socket and worker sockets and fork
    # between privileged parent and unprivileged child.
    ($PRIVILEGED_PARENT_PID, my $worker_socks_ref, $MAIN_PRIV_SOCK) =
	setup_privsep_per_worker ($fork_children);

    @WORKER_SOCKETS = @$worker_socks_ref;

    # At this point we're now an unprivileged child process.
    # Re-pledge to remove @UNVEIL_PROMISE,
    # @PRIVSEP_PRIV_PROMISES, and @PRIVSEP_DROPPRIV_PROMISES.
    # Also removing @CHANGE_ATTR_PROMISES. Need @EXEC_PROMISES
    # if using pgp for initialize and update operations.
    # 'flock' required for main changed file but not for child
    # ones, child workers could drop it.
    if ($^O eq 'openbsd') {
	my @promises = (@READONLY_PROMISES, @READWRITE_PROMISES,
			@EXEC_PROMISES, @FLOCK_PROMISE,
			@PRIVSEP_NONPRIV_PROMISES);
	# stdio is automatically included
	pledge (@promises) || die "Cannot pledge child nonpriv promises. $!\n";
    }

    # If no additional workers, FileAttr needs to use the main
    # privileged socket instead of a worker one.
    # FileAttr needs to use the main privileged socket when used
    # from the unprivileged parent of the worker processes.
    # Each worker will change this for themselves.
    $FileAttr::PRIV_IPC = $MAIN_PRIV_SOCK;
}

if ($command eq 'initialize') {
    initialize_sets ($config, $ALL, @sets);
}
elsif ($command eq 'initialize_specs') {
    initialize_sets ($config, $SPECS_ONLY, @sets);
}
elsif ($command eq 'changes') {
    if ($^O eq 'openbsd') {
	# 'flock' required for changed file.
	# Now need special treatment with privsep.
	my @promises = (@READONLY_PROMISES, @FLOCK_PROMISE);
	push (@promises, @PRIVSEP_NONPRIV_PROMISES) if ($use_privsep);
	# A spec or path asked about: its paths' flags are read with ls.
	push (@promises, @EXEC_PROMISES) if (defined ($changes_query));
	pledge (@promises) || die "Cannot pledge read-only promises. $!\n";
    }
    # 0: changes pending; 1: none; 2: an error. die's own exit status
    # depends on $!, which could be 1, so an error is caught and mapped.
    my $changes_status = eval { show_changes ($config, $no_macos_app_contents, $changes_query, @sets) };
    if (!defined ($changes_status)) {
	print STDERR $@;
	exit (2);
    }
    exit ($changes_status);
}
elsif ($command eq 'check') {
    if ($^O eq 'openbsd') {
	# Don't need 'fattr' (@CHANGE_ATTR_PROMISES),
	# or 'unveil' (@UNVEIL_PROMISE)
	# 'flock' required for changed file.
	my @promises = (@READONLY_PROMISES, @READWRITE_PROMISES,
			@EXEC_PROMISES, @FLOCK_PROMISE);
	push (@promises, @PRIVSEP_NONPRIV_PROMISES) if ($use_privsep);
	pledge (@promises) || die "Cannot pledge check promises. $!\n";
    }
    check_sets ($config, $ALL, @sets);
}
elsif ($command eq 'check_file') {
    if ($^O eq 'openbsd') {
	# Don't need 'fattr' (@CHANGE_ATTR_PROMISES), 'unveil' (@UNVEIL_PROMISE).
	# 'flock' required for changed file.
	my @promises = (@READONLY_PROMISES, @READWRITE_PROMISES,
			@EXEC_PROMISES, @FLOCK_PROMISE);
	push (@promises, @PRIVSEP_NONPRIV_PROMISES) if ($use_privsep);
	pledge (@promises) || die "Cannot pledge check promises. $!\n";
    }
    check_sets ($config, $SUBTREE_ONLY, $file);
}
elsif ($command eq 'check_specs') {
    if ($^O eq 'openbsd') {
	# Don't need 'fattr' (@CHANGE_ATTR_PROMISES), 'unveil' (@UNVEIL_PROMISE),
	# 'flock' required for changed file.
	my @promises = (@READONLY_PROMISES, @READWRITE_PROMISES,
			@EXEC_PROMISES, @FLOCK_PROMISE);
	push (@promises, @PRIVSEP_NONPRIV_PROMISES) if ($use_privsep);
	pledge (@promises) || die "Cannot pledge check promises. $!\n";
    }
    check_sets ($config, $SPECS_ONLY, @sets)
}
elsif ($command eq 'update') {
    update_sets ($config, @sets);
}

### Subroutines.

# Subroutine to make check_file's absolute path canonical, as the spec
# records paths: no "//", "/./" or trailing "/", and ".." resolved. Before
# 1.32, "check_file dir/" or "../file" was looked up as "dir/" or
# "sub/../file", recorded as added under that name, and an update put the
# name in the spec, where no check ever looks at it again. ".." is
# resolved by removing the component before it, which is what the kernel
# does unless that component is a symbolic link (then ".." is the link
# target's parent), so in that case the path is refused. realpath is not
# used: it would follow a symlink being checked, and turn a path through
# a symlinked directory (/etc on macOS is /private/etc) into one that
# matches no tree.
sub canonical_check_path {
    my ($path) = @_;
    my @components;

    foreach my $component (split (m{/+}, $path)) {
	next if ($component eq '' || $component eq '.');
	if ($component eq '..') {
	    my $before = '/' . join ('/', @components);
	    die "Cannot resolve \"..\" after the symbolic link " . AttrDisplay::esc ($before) .
		"; give the path without \"..\".\n" if (@components && -l $before);
	    pop (@components);
	    next;
	}
	push (@components, $component);
    }
    return '/' . join ('/', @components);
}

# Subroutine to assist in optional module importing.
# (Also used in reportnew.)
sub require_module {
    my ($module, @imports) = @_;

    if (!eval "require $module; 1") {
        return 0;
    }

    if (@imports) {
        $module->import (@imports);
    }

    return 1;
}

# Subroutine to initialize sets.  We initialize all trees that contain
# any references to the sets specified--including exceptions that may
# not be members of those sets.
sub initialize_sets {
    my ($config, $specs_only, @sets) = @_;
    my ($pgp_passphrase, 
	$changed_file_exists, $changedfile, $changed_specs, @changed_trees,
	@trees, $tree, $tree_spec_name, @specified_trees);
    # used for Parallel::ForkManager
    my ($pm, $child_temp_dir);
    my @failed_trees; # Trees whose worker did not finish normally.

    $| = 1;

    if ($specs_only) {
	print "Warning: This command will cause any changes to your specifications dir\n";
	print "to be lost, and should only be used to wipe out changes which have\n";
	print "occurred to that dir for reasons such as a system dump (which causes\n";
	print "an inode change.  If you are at all uncertain, use the initialize\n";
	print "command to re-initialize all of the specifications themselves.\n";

	exit if (!yes_or_no ('Proceed? '));
	
    }

    $pgp_passphrase = get_pgp_passphrase() if ($use_pgp);
    # Stop now, before any spec is changed, if the passphrase cannot sign.
    check_passphrase ($pgp_passphrase) if ($use_pgp);

    if (!$specs_only) {
	# With privsep, we can't do -e checks after dropping privileges
	# so we collect all spec existence info before privsep in @EXISTING_SPECS
	if ((!$use_privsep && -e $changed_file) ||
	    ($use_privsep && grep { $_ eq $changed_file } @EXISTING_SPECS)) {
	    $changed_file_exists = 1;
	    $changedfile = new ChangedFile ($changed_file);
	    if ($changedfile) {
		$changed_specs = $changedfile->tree_present ($spec_dir);
	    }
	    else {
		warn "Failed to load changed file, treating it as if it doesn't exist.\n";
		$changed_file_exists = 0;
	    }
	    if ($verbose && $changed_file_exists) {
		print "A changed file exists.  We will remove any trees we initialize from it.\n";
		print "There are changed specifications, we will re-initialize them.\n" if ($changed_specs);
	    }
	}
	
	print "Initializing specifications.\n" if ($verbose);

	# This goes through all trees in the config, but leaves in the
	# changed file any trees that are no longer in the config.
	@trees = $config->all_trees;

	foreach $tree (@trees) {
	    push (@specified_trees, $tree) if ($config->tree_uses_sets ($tree, @sets));
	}
	# Don't fork unnecessarily.
	if (scalar (@specified_trees) < $fork_children) {
	    $fork_children = scalar (@specified_trees);
	    $fork_children = 0 if (scalar (@specified_trees) == 1);
	}

	# Track available worker slots
	my @available_workers = (0 .. $fork_children - 1);  # Initially all available
	my %worker_in_use;  # Track which workers are busy

	# Split this up among children. This children will produce some
	# output if verbose but don't need to coordinate with the parent
	# like in check_sets.
	if ($fork_children) {
	    # create $child_temp_dir with mktemp
	    $child_temp_dir = mkdtemp ('/tmp/sigtree.XXXXXXXX') or
		die "Could not create temp dir in /tmp: $!\n";
	    chomp ($child_temp_dir);
	    $pm = Parallel::ForkManager->new ($fork_children,
					      $child_temp_dir);

	    # Set up handler for when each child finishes.
	    $pm->run_on_finish (
		sub {
		    my ($pid, $exit_code, $ident, $exit_signal, $core_dump, $tree_ref) = @_;
		    my ($child_tree);
		    
		    # The ident is the tree name
		    # Look up which worker this tree was using
		    my $finished_worker_id = delete $worker_in_use{$ident};
        
		    if (defined $finished_worker_id) {
			# Return this worker to available pool
			push @available_workers, $finished_worker_id;
            
			if ($main::debug_flag) {
			    print "DEBUG: [MAIN] Worker $finished_worker_id finished tree $ident (PID $pid)\n";
			    print "DEBUG: [MAIN] Worker $finished_worker_id now available\n";
			    print "DEBUG: [MAIN] Available workers: " . join(", ", sort @available_workers) . "\n";
			}
		    }
			
		    # Only a worker that exited 0 and returned its tree name
		    # initialized its tree. Any other ending (a die, a signal,
		    # lost return data) leaves the tree's changes in the
		    # changed file, so they are not lost.
		    if ($exit_code == 0 && !$exit_signal && defined ($tree_ref)) {
			$child_tree = ${$tree_ref};
			# Need to do this check again, only remove if it was in a specified set.
			if ($config->tree_uses_sets ($child_tree, @sets) &&
			    $changed_file_exists && $changedfile->tree_present ($child_tree)) {
			    $changedfile->delete ($child_tree);
			}
		    }
		    else {
			push (@failed_trees, $ident // "pid $pid");
			print "Warning: child for tree " . ($ident // "(unknown)") . " (pid $pid) failed (" .
			    ($exit_signal ? "signal $exit_signal" : "exit $exit_code") .
			    "); its changes are kept in the changed file.\n";
		    }
		}
		);
	}

	foreach $tree (@specified_trees) {
	    if ($fork_children) {
		# Wait for an available worker slot
		while (!@available_workers) {
		    # Reap finished children to trigger run_on_finish callback
		    # which returns workers to @available_workers
		    $pm->reap_finished_children();
		    # Short sleep to avoid busy-waiting
		    select(undef, undef, undef, 0.1);
		}
		
		# Get next available worker ID
		my $current_worker_id = shift @available_workers;
        
		# Track that this tree is using this worker
		$worker_in_use{$tree} = $current_worker_id;
        
		if ($main::debug_flag) {
		    print "DEBUG: [MAIN] Assigning tree $tree to worker $current_worker_id\n";
		    print "DEBUG: [MAIN] Available workers: " . join(", ", sort @available_workers) . "\n";
		    print "DEBUG: [MAIN] Workers in use: " . 
			join(", ", map { "$_=>$worker_in_use{$_}" } sort keys %worker_in_use) . "\n";
		}
		
		$pm->start ($tree) and next;

		# In a new worker child process, switch the socket to
		# the worker and close the others.
		if ($use_privsep) {
		    # Set socket we use.
		    $FileAttr::PRIV_IPC = $WORKER_SOCKETS[$current_worker_id];
		    # Close sockets we don't need.
		    close $MAIN_PRIV_SOCK;

		    # Set descriptive process name.
		    $0 = "sigtree worker $current_worker_id";
		    
		    # Undef other worker sockets rather than closing them
		    # because closing would affect the parent's copies via socketpair
		    for my $idx (0..$#WORKER_SOCKETS) {
			if ($idx != $current_worker_id) {
			    $WORKER_SOCKETS[$idx] = undef;
			}
		    }
		}
	    }
	    
	    $tree_spec_name = path_to_spec ($tree);

	    if ($use_privsep && $use_immutable) {
		PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, $spec_dir, $IMMUTABLE_OFF);
		PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, "$spec_dir/$tree_spec_name", $IMMUTABLE_OFF);
		if ($use_pgp) {
		    PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, "$spec_dir/$tree_spec_name.sig", $IMMUTABLE_OFF);
		}
	    }
	    elsif ($use_immutable) {
		set_immutable_flag ($spec_dir, $IMMUTABLE_OFF);
		set_immutable_flag ("$spec_dir/$tree_spec_name", $IMMUTABLE_OFF);
		if ($use_pgp) {
		    set_immutable_flag ("$spec_dir/$tree_spec_name.sig", $IMMUTABLE_OFF);
		}
	    }
	    if ($verbose) {
		print "$tree";
		print ": start child" if ($fork_children);
		print "\n";
	    }
	    create_tree ($config, $TREE_ROOT, $tree, '.', '', "$spec_dir/$tree_spec_name");
	    if ($use_pgp) {
		sigtree_sign ("$spec_dir/$tree_spec_name", $pgp_passphrase);
	    }
	    if ($use_privsep && $use_immutable) {
		PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, "$spec_dir/$tree_spec_name", $IMMUTABLE_ON);
		if ($use_pgp) {
		    PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, "$spec_dir/$tree_spec_name.sig", $IMMUTABLE_ON);
		}
	    }
	    elsif ($use_immutable) {
		set_immutable_flag ("$spec_dir/$tree_spec_name", $IMMUTABLE_ON);
		if ($use_pgp) {
		    set_immutable_flag ("$spec_dir/$tree_spec_name.sig", $IMMUTABLE_ON);
		}
	    }

	    # Remove this tree from the changed file if present.
	    # Parent needs to do this if forking children.
	    if (!$fork_children) {
		if ($changed_file_exists && $changedfile->tree_present ($tree)) {
		    $changedfile->delete ($tree);
		}
	    }

	    if ($fork_children) {
		print "$tree: finish child\n" if ($verbose);
		# Return the tree name.
		$pm->finish (0, \$tree);
	    }

	} # foreach $tree loop
	
    } # !$specs_only

    if ($fork_children) {
	# Wait for all children to finish.
	$pm->wait_all_children;
	# Remove $child_temp_dir.
	remove_temp_dir ($child_temp_dir);
    }

    # If we reinitialized any changed specs, delete spec_dir from the
    # changed file, along with any trees that are no longer in the
    # config.  Save our changes, and delete the file if it's
    # now empty.
    if ($changed_file_exists) {
	if ($changed_specs) {
	    # Delete the spec_dir from the changed file.
	    $changedfile->delete ($spec_dir);
	    # Delete any trees from the changed file that are no longer
	    # in the config.
	    @changed_trees = $changedfile->get_trees;
	    foreach $tree (@changed_trees) {
		$changedfile->delete ($tree) if (!grep { $_ eq $tree } @trees);
	    }
	}
	$changedfile->store_changedfile();
	$changedfile->delete_if_empty();
    }

    print "Initializing specification for specification dir.\n" if ($verbose);
    if ($use_privsep && $use_immutable) {
	PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, "$spec_dir_dir/$spec_spec", $IMMUTABLE_OFF);
	if ($use_pgp) {
	    PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, "$spec_dir_dir/$spec_spec.sig", $IMMUTABLE_OFF);
	}
    }
    elsif ($use_immutable) {
	set_immutable_flag ("$spec_dir_dir/$spec_spec", $IMMUTABLE_OFF);
	if ($use_pgp) {
	    set_immutable_flag ("$spec_dir_dir/$spec_spec.sig", $IMMUTABLE_OFF);
	}
    }
    # This must be done before the specification for the specification dir
    # is created, since changing flags involves inode modification.
    if ($use_privsep && $use_immutable) {
	PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, $spec_dir, $IMMUTABLE_ON);
    }
    elsif ($use_immutable) {
	set_immutable_flag ($spec_dir, $IMMUTABLE_ON);
    }
    create_tree ($config, $TREE_ROOT, $spec_dir, '.', '', "$spec_dir_dir/$spec_spec");
    if ($use_pgp) {
	sigtree_sign ("$spec_dir_dir/$spec_spec", $pgp_passphrase);
    }
    if ($use_privsep && $use_immutable) {
	PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, "$spec_dir_dir/$spec_spec", $IMMUTABLE_ON);
	if ($use_pgp) {
	    PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, "$spec_dir_dir/$spec_spec.sig", $IMMUTABLE_ON);
	}
    }
    elsif ($use_immutable) {
	set_immutable_flag ("$spec_dir_dir/$spec_spec", $IMMUTABLE_ON);
	if ($use_pgp) {
	    set_immutable_flag ("$spec_dir_dir/$spec_spec.sig", $IMMUTABLE_ON);
	}
    }

    # Overwrite the passphrase now that signing is done.
    if (defined ($pgp_passphrase)) {
	$pgp_passphrase = "x" x length ($pgp_passphrase);
	$pgp_passphrase = '';
    }

    if (@failed_trees) {
	die "Initialization failed for " . scalar (@failed_trees) . " tree(s): @failed_trees\n" .
	    "Their changes are still in the changed file; fix the cause and initialize them again.\n";
    }
}

# Subroutine to create trees.  If first arg is $TREE_ROOT, then
# it's the primary invocation, and we have to create the spec_path
# at the end.  Otherwise, we're in a recursive invocation and
# we are just building the tree.
sub create_tree {
    my ($config, $tree_root, $tree, $path, $spec, $spec_path) = @_;
    my ($fileattr, $file, $full_path);

    return if ($config->path_is_ignored ($tree, $path));

    if ($tree_root) {
	if (!writable_file ($spec_path)) {
	    print "Specification is not writable. Skipping. $spec_path\n";
	    return;
	}
	# With privsep, the actual writability will be determined when
	# we try to open the spec, if it fails, request_open will return
	# undef and we'll get an error there.
	($spec, $fileattr) = new Spec ($tree);
	unless ($spec && $fileattr) {
	    print "Failed to load spec for $tree, skipping.\n";
	    return;
	}
    }
    else {
	$fileattr = $spec->add ($tree, $path);
    }
    if ($fileattr->{TYPE} eq 'dir') {
	# Read the entries' flags in batches rather than one ls each.
	FileAttr::prefetch_flags ($tree, map { $tree_root ? $_ : "$path/$_" } @{$fileattr->{FILES}});
        foreach $file (@{$fileattr->{FILES}}) {
	    $full_path = $file;
	    if (!$tree_root) {
		$full_path = $path . '/' . $file;
	    }
            create_tree ($config, $SUBTREE, $tree, $full_path, $spec);
        }
    }
    if ($tree_root) {
	$spec->store_spec ($spec_path);
    }
}

# Subroutine to display contents of changed file (for specified sets).
sub show_changes {
    my ($config, $no_macos_app_contents, $query, @sets) = @_;
    my ($changedfile, $displayed_something, @changed_trees, $tree,
	@times, @users, @paths, $time, $user, $path, %entries, $hidden);

    # Exit status: 0 if changes are pending in the specified sets (and
    # under the spec or path asked about), 1 if none are (including no
    # changed file), so cron can run update only when needed; an error
    # exits 2.
    if ((!$use_privsep && !-e $changed_file) ||
	($use_privsep && !grep { $_ eq $changed_file } @EXISTING_SPECS)) {
	print "No pending changes (there is no changed file).\n";
	return 1;
    }

    $changedfile = new ChangedFile ($changed_file);
    unless ($changedfile) {
	die "Failed to load changed file: $changed_file\n";
    }

    return show_change_query ($config, $changedfile, $no_macos_app_contents, $query, @sets)
	if (defined ($query));

    $displayed_something = 0;

    @changed_trees = $changedfile->get_trees;
    %entries = map { ($_->{PATH} => $_) } $changedfile->get_entries;

    foreach $tree (@changed_trees) {
	if ($tree ne $spec_dir && !$config->tree_for_path ($tree)) {
	    print "Changed file contains tree which is not in config file. $tree\n";
	}
	elsif ($tree eq $spec_dir || 
	    $config->tree_uses_sets ($tree, @sets)) {
	    $displayed_something = 1;
	    print "tree: $tree";
	    print " (specification dir)" if ($tree eq $spec_dir);
	    print " (macOS app)" if ($no_macos_app_contents && $tree =~ /$MACOS_APP/);
	    print "\n";
	    @times = $changedfile->get_times ($tree);
	    @users = $changedfile->get_users ($tree);
	    print "This tree was checked and changes were found on:\n";
	    foreach $time (@times) {
		$time = localtime ($time);
		$user = shift (@users);
		print "   $time by $user\n";
	    }
	    print "The following paths in this tree have changed:\n";
	    @paths = $changedfile->get_paths ($tree);
	    $hidden = 0;
	    my %apps;
	    # Each with what changed: its changed attributes (only those -k
	    # names, if it is given), or that it was added or deleted.
	    foreach $path (@paths) {
		my $full = ($path eq '.') ? $tree : "$tree/$path";
		my $entry = $entries{$full};
		if ($no_macos_app_contents && defined (my $app = _macos_app ($full))) {
		    $apps{$app}{$entry ? $entry->{KIND} : 'changed'}++;
		    next;
		}
		my $note = '';
		if ($entry && $entry->{KIND} ne 'changed') {
		    $note = " ($entry->{KIND})";
		}
		elsif ($entry) {
		    my @shown = AttrDisplay::shown (_ordered_attrs (@{$entry->{ATTRS}}));
		    if (!@shown && @{$entry->{ATTRS}}) {
			$hidden++;
			next;
		    }
		    $note = " (" . join (',', @shown) . ")" if (@shown);
		}
		$note .= " (macOS app)" if ($no_macos_app_contents && $path =~ /$MACOS_APP/);
		print "   " . AttrDisplay::esc ($path) . "$note\n";
	    }
	    print "   ($hidden more changed only in attributes -k leaves out)\n" if ($hidden);
	    print map { "   $_\n" } _macos_app_lines (\%apps);
	}
    }

    if (!$displayed_something) {
	print "No pending changes in the specified sets.\n";
	return 1;
    }
    elsif ($verbose) {
	# Args are changedfile, verbose flag, write flag, no_macos_app_contents
	show_change_details ($changedfile, 0, 0, $no_macos_app_contents);
    }
    return 0;
}

# Attributes in the order they are shown (any unknown ones last, as
# recorded).
sub _ordered_attrs {
    my (@attrs) = @_;
    my $n = 0;
    my %order = map { ($_ => $n++) } AttrDisplay::attrs ();
    return sort { ($order{$a} // $n) <=> ($order{$b} // $n) } @attrs;
}

# A changed path's attributes as the summary shows them: with the values
# in the spec and found by the check, digests shortened, if the changed
# file has them (1.31 and later), or else their names. Only those -k
# names; undef if it names none of them.
sub _change_summary {
    my ($attrs, $values) = @_;
    my @attrs = _ordered_attrs (@{$attrs});
    my @shown = AttrDisplay::shown (@attrs);

    return undef if (@attrs && !@shown);
    return join (',', @shown) unless ($values);
    return join ('; ', map { ($values && $values->{$_}) ?
				 AttrDisplay::change ($_, @{$values->{$_}}, 'short' => 1) : $_ } @shown);
}

# Subroutine for "changes spec" and "changes /path": each pending path in
# that spec's tree, or at or beneath that path, with what the check found
# (the spec's value and the value found, for each changed attribute;
# with -v, in check's long form), and whether the path is still as the
# check found it. For that it is looked at again now (and digested, if
# its digest changed), so a change that has been undone since, or a
# further change, is reported.
sub show_change_query {
    my ($config, $changedfile, $no_macos_app_contents, $query, @sets) = @_;
    my (@trees, %tree_ok, @entries, $label, $hidden, $last_tree);

    @trees = grep { $_ eq $spec_dir || ($config->tree_for_path ($_) && $config->tree_uses_sets ($_, @sets)) }
	$changedfile->get_trees;
    %tree_ok = map { ($_ => 1) } @trees;
    @entries = grep { $tree_ok{$_->{TREE}} } $changedfile->get_entries;

    if ($query =~ m{^/}) {
	($label = $query) =~ s{(?<=.)/+\z}{};
	my $prefix = ($label eq '/') ? '/' : "$label/";
	@entries = grep { $_->{PATH} eq $label || index ($_->{PATH}, $prefix) == 0 } @entries;
    }
    else {
	# A spec name, as the spec files are named (etc for /etc,
	# usr.local for /usr/local), or the spec of specs.
	my @named = grep { path_to_spec ($_) eq $query } $config->all_trees;
	push (@named, $spec_dir) if ($query eq $spec_spec || $query eq path_to_spec ($spec_dir));
	die "No tree in the config has the spec name \"" . AttrDisplay::esc ($query) .
	    "\" (they are: " . join (', ', sort (map { path_to_spec ($_) } $config->all_trees)) .
	    "; or a path, starting with /).\n" unless (@named);
	my %named = map { ($_ => 1) } @named;
	@entries = grep { $named{$_->{TREE}} } @entries;
	$label = "spec $query";
    }
    # With -m, paths inside a macOS app are counted per app, unless the
    # path asked about is that app or inside it.
    my %apps;
    if ($no_macos_app_contents) {
	@entries = grep {
	    my $app = _macos_app ($_->{PATH});
	    my $collapse = defined ($app) &&
		!($query =~ m{^/} && ($label eq $app || index ($label, "$app/") == 0));
	    $apps{$app}{$_->{KIND}}++ if ($collapse);
	    !$collapse } @entries;
    }

    unless (@entries || %apps) {
	print "No pending changes for " . AttrDisplay::esc ($label) .
	    ((@sets && $set) ? " in the specified sets" : '') . ".\n";
	return 1;
    }

    $hidden = 0;
    foreach my $entry (sort { $a->{TREE} cmp $b->{TREE} || $a->{PATH} cmp $b->{PATH} } @entries) {
	my $tree = $entry->{TREE};
	my $rel = ($entry->{PATH} eq $tree) ? '.' :
	    substr ($entry->{PATH}, length ($tree) + (($tree eq '/') ? 0 : 1));
	my (@lines, @shown);

	if ($entry->{KIND} eq 'changed') {
	    my @attrs = _ordered_attrs (@{$entry->{ATTRS}});
	    @shown = AttrDisplay::shown (@attrs);
	    if (@attrs && !@shown) {
		$hidden++;
		next;
	    }
	}

	if (!defined ($last_tree) || $last_tree ne $tree) {
	    my @times = $changedfile->get_times ($tree);
	    my @users = $changedfile->get_users ($tree);
	    print "\n" if (defined ($last_tree));
	    print "tree: $tree" . (($tree eq $spec_dir) ? " (specification dir)" : '');
	    print ", last checked " . localtime ($times[-1]) . " by $users[-1]" if (@times);
	    print "\n";
	    $last_tree = $tree;
	}

	my ($description, $keywords, $priority) = $config->set_info ($entry->{SET});
	print "" . AttrDisplay::esc ($entry->{PATH}) . " (set $entry->{SET}" .
	    (defined ($priority) ? ", priority $priority" : '') . "):\n";

	if ($entry->{KIND} eq 'added') {
	    push (@lines, "   added");
	}
	elsif ($entry->{KIND} eq 'deleted') {
	    push (@lines, "   deleted");
	}
	elsif (!$entry->{VALUES}) {
	    push (@lines, "   changed: " . join (', ', @shown) .
		  " (the changed file is from before 1.31 and holds no values)");
	}
	else {
	    foreach my $attr (@shown) {
		my $pair = $entry->{VALUES}{$attr} or next;
		push (@lines, $verbose ? AttrDisplay::long_lines ($attr, @{$pair}) :
		      "   " . AttrDisplay::change ($attr, @{$pair}));
	    }
	}
	push (@lines, _since_check ($config, $entry, $tree, $rel));
	print map { "$_\n" } @lines;
    }
    print "($hidden more changed only in attributes -k leaves out)\n" if ($hidden);
    if (%apps) {
	print "\n" if (@entries);
	print map { "$_\n" } _macos_app_lines (\%apps);
    }
    return 0;
}

# The macOS app a path is inside (the outermost, for an app within an
# app), or undef. Used with -m, which shows changes inside an app as
# counts for the app rather than one by one.
sub _macos_app {
    my ($path) = @_;
    return ($path =~ m{^(.*?\.app)/}) ? $1 : undef;
}

# Lines counting the changes inside each macOS app (-m), from app =>
# { changed => n, added => n, deleted => n }.
sub _macos_app_lines {
    my ($apps) = @_;
    return () unless (%{$apps});
    return ("Inside macOS apps (not listed with -m):",
	    map { my $count = $apps->{$_};
		  "   " . AttrDisplay::esc ($_) . ": " .
		      join (', ', map { "$count->{$_} $_" } grep { $count->{$_} } qw(changed added deleted)) }
	    sort (keys (%{$apps})));
}

# How a pending path differs now from what the check found, as lines to
# show (none if it is as the check found it).
sub _since_check {
    my ($config, $entry, $tree, $rel) = @_;
    my (@attrs, $digest, $now, @again, $reverted, $modified);

    if ($entry->{KIND} eq 'changed') {
	return () unless ($entry->{VALUES});
	@attrs = grep { $entry->{VALUES}{$_} } _ordered_attrs (@{$entry->{ATTRS}});
	return () unless (@attrs);
    }
    # The digest only if the check found it changed.
    $digest = (grep { $_ eq 'shadigest' } @attrs) ? $config->path_sha_digest ($tree, $rel) : 0;
    $now = new FileAttr ($tree, $rel, $digest);

    if ($entry->{KIND} eq 'added') {
	return ($now->{TYPE} eq 'nonexistent') ? ("   since removed: as in the spec again") : ();
    }
    if ($entry->{KIND} eq 'deleted') {
	return ($now->{TYPE} ne 'nonexistent') ? ("   since restored: exists again (now a $now->{TYPE})") : ();
    }
    return ("   since deleted") if ($now->{TYPE} eq 'nonexistent');

    my $same = sub { my ($x, $y) = @_;
		     return (!defined ($x) && !defined ($y)) ||
			 (defined ($x) && defined ($y) && $x eq $y) };
    $reverted = 1;
    foreach my $attr (@attrs) {
	my ($old, $new) = @{$entry->{VALUES}{$attr}};
	my $current = $now->{AttrDisplay::field ($attr)};
	if ($attr eq 'mtimestasis') {
	    # Modified at last: no longer unchanged since $old.
	    $reverted = 0;
	    $modified = AttrDisplay::value ('mtime', $current) unless ($same->($current, $old));
	}
	elsif ($same->($current, $old)) {
	    next;
	}
	else {
	    $reverted = 0;
	    # In the form of the lines above it, indented under it.
	    push (@again, $verbose ? (map { "   $_" } AttrDisplay::long_lines ($attr, $new, $current)) :
		  "      " . AttrDisplay::change ($attr, $new, $current))
		unless ($same->($current, $new));
	}
    }
    return ("   since reverted: as in the spec again (an update would record no change)")
	if ($reverted);
    return (($modified ? ("   modified since the check (mtime now $modified)") : ()),
	    (@again ? ("   changed again since the check:", @again) : ()));
}

# Subroutine to check sets.  We check all trees that contain references
# to the sets we've been requested to check, but only look at the
# particular items which are members of those sets (i.e., we ignore
# exceptions that aren't members of the specified sets), and only
# check for differences based on the keywords associated with the
# primary set of each tree or exception path.  If we hit a directory
# that isn't in the sets, we still check its subtree because it may
# have some other exceptions in its subtree that are in the specified
# sets (we only make note of/do actual comparisons on such exceptions).
#
# I think this is still accurate with modifications to reduce the
# number of trees checked, and is the opposite of what is suggested
# in the comments in the sample config file.
#
# The original intention was that sets with only descriptions were
# intended for use with -s and sets with keywords were intended for
# identifying attributes to check and for exceptions, but not for use with
# -s. They do in fact work with -s, and now if you use -s root, it
# will only check /root.
sub check_sets {
    my ($config, $specs_only, @sets) = @_;
    my ($subtree_only, $changedfile, @specified_trees,
	@trees, $tree, $tree_spec_name,
	@changed_sets, $set, $priority, $keywords, $description, $path);
    # used for Parallel::ForkManager
    my ($pm, $child_temp_dir, $child_temp_file, $child_changedfile);

    $| = 1;
    
    if ($specs_only == $SUBTREE_ONLY) {
	$specs_only = 0;
	$subtree_only = 1;
	$path = $sets[0];
    }

    $changedfile = new ChangedFile ($changed_file);
    unless ($changedfile) {
	die "Failed to load changed file: $changed_file\n";
    }

    # Keep a copy of the previous results, for any tree whose worker
    # fails below, then clear the current contents of the changed file.
    my $previous_changedfile = $changedfile->copy;
    $changedfile->reset_changed_file;

    print "Checking for extraneous files in specification dir.\n" if ($verbose);
    display_extraneous_files ($config, $spec_dir, $verbose);

    print "Checking to see if specification dir has changed.\n" if ($verbose);
    print "$spec_dir\n" if ($verbose);
    if ($use_pgp) {
	sigtree_verify ("$spec_dir_dir/$spec_spec");
    }
    check_tree ($config, $TREE_ROOT, $spec_dir, '.', '', $changedfile, "$spec_dir_dir/$spec_spec");
    # As for every tree: before 1.31 the spec dir had no check time, so
    # changes died (exit 2) whenever check had found it changed.
    $changedfile->add_time ($spec_dir);

    print "\nChecking individual specifications." if ($verbose && !$specs_only);
    if ($subtree_only) {
	@trees = $config->tree_for_path ($path);
	if (!$trees[0]) {
	    print "\n" if ($verbose);
	    die "File is not in any specifications. $path\n";
	}
	# If path is a tree, we just do the whole tree as normal.
	elsif ($trees[0] eq $path) {
	    $path = '.';
	}
	else {
	    $path =~ s/^\Q$trees[0]\E\///;
	}
    }
    else {
	@trees = $config->all_trees;
	$path = '.';
    }

    # Make check behave like initialize. For check_file, @trees is the
    # file's tree and @sets holds the file's path, not sets: before 1.31
    # that tree was dropped here, so check_file checked only the spec dir.
    foreach $tree (@trees) {
	push (@specified_trees, $tree) if ($subtree_only || $config->tree_uses_sets ($tree, @sets));
    }
    # Don't fork unnecessarily.
    if (scalar (@specified_trees) < $fork_children) {
	$fork_children = scalar (@specified_trees);
	$fork_children = 0 if (scalar (@specified_trees) == 1);
    }
    
    # Track available worker slots
    my @available_workers = (0 .. $fork_children - 1);  # Initially all available
    my %worker_in_use;  # Track which workers are busy
    my @failed_trees;   # Trees whose worker did not finish normally

    if ($fork_children) {
	# create $child_temp_dir with mktemp
	$child_temp_dir = mkdtemp ('/tmp/sigtree.XXXXXXXX') or
	    die "Could not create temp dir in /tmp: $!\n";
	chomp ($child_temp_dir);
	$pm = Parallel::ForkManager->new ($fork_children,
					  $child_temp_dir);

	# Set up handler for when each child finishes.
	$pm->run_on_finish (
	    sub {
		my ($pid, $exit_code, $ident, $exit_signal, $core_dump, $tempfile_ref) = @_;

		# The ident is the tree name
		# Look up which worker this tree was using
		my $finished_worker_id = delete $worker_in_use{$ident};
        
		if (defined $finished_worker_id) {
		    # Return this worker to available pool
		    push @available_workers, $finished_worker_id;
            
		    if ($main::debug_flag) {
			print "DEBUG: [MAIN] Worker $finished_worker_id finished tree $ident (PID $pid)\n";
			print "DEBUG: [MAIN] Worker $finished_worker_id now available\n";
			print "DEBUG: [MAIN] Available workers: " . join(", ", sort @available_workers) . "\n";
		    }
		}
        
		if ($exit_code == 0 && !$exit_signal && defined ($tempfile_ref)) {
		    # Get the returned filename.
		    $child_temp_file = ${$tempfile_ref};
		    # Retrieve from stored.
		    $child_changedfile = new ChangedFile ("$child_temp_dir/$child_temp_file", 1);
		    if ($child_changedfile) {
			# Merge into main one.
			$changedfile->merge ($child_changedfile);
		    }
		    else {
			push (@failed_trees, $ident);
			warn "Failed to load child changed file: $child_temp_dir/$child_temp_file\n";
		    }
		    # Remove the file.
		    unlink ("$child_temp_dir/$child_temp_file");
		}
		else {
		    # Child failed: its tree's results from this run are
		    # missing, so its previous results are kept (see below).
		    push (@failed_trees, $ident // "pid $pid");
		    print "Warning: child for tree " . ($ident // "(unknown)") . " (pid $pid) failed (" .
			($exit_signal ? "signal $exit_signal" : "exit $exit_code") . ").\n";
		}
	    }
	    );
    }

    # What this check covers, by tree: '.' for the whole tree, or for
    # check_file the path checked. The changed file's records for
    # everything else (other sets' trees, the rest of a tree for
    # check_file, all trees for check_specs, and trees whose worker
    # fails) are kept from the previous check; before 1.31 every check
    # replaced them all. The spec dir is checked every time.
    my %covered;
    foreach $tree (@specified_trees) {
	$tree_spec_name = path_to_spec ($tree);
	next if ($specs_only ||
		 (!$use_privsep && !-e "$spec_dir/$tree_spec_name") ||
		 ($use_privsep && !grep { $_ eq $tree_spec_name } @EXISTING_SPECS));
	$covered{$tree} = $path;
    }

    foreach $tree (@specified_trees) {
	if ($fork_children) {
	    # Wait for an available worker slot
	    while (!@available_workers) {
		# Reap finished children to trigger run_on_finish callback
		# which returns workers to @available_workers
		$pm->reap_finished_children();
		# Short sleep to avoid busy-waiting
		select(undef, undef, undef, 0.1);
	    }
        
	    # Get next available worker ID
	    my $current_worker_id = shift @available_workers;
	    
	    # Track that this tree is using this worker
	    $worker_in_use{$tree} = $current_worker_id;
        
	    if ($main::debug_flag) {
		print "DEBUG: [MAIN] Assigning tree $tree to worker $current_worker_id\n";
		print "DEBUG: [MAIN] Available workers: " . join(", ", sort @available_workers) . "\n";
		print "DEBUG: [MAIN] Workers in use: " . 
		    join(", ", map { "$_=>$worker_in_use{$_}" } sort keys %worker_in_use) . "\n";
	    }
	    
	    $pm->start ($tree) and next;

	    # In a new worker child process, switch the socket to
	    # the worker and close the others.	    
	    if ($use_privsep) {
		# Set socket we use.
		$FileAttr::PRIV_IPC = $WORKER_SOCKETS[$current_worker_id];
		# Close sockets we don't need.
		close $MAIN_PRIV_SOCK;

		# Set descriptive process name.
		$0 = "sigtree worker $current_worker_id";
		    
		# Undef other worker sockets rather than closing them
		# because closing would affect the parent's copies via socketpair
		for my $idx (0..$#WORKER_SOCKETS) {
		    if ($idx != $current_worker_id) {
			$WORKER_SOCKETS[$idx] = undef;
		    }
		}
	    }
	    
	    # Create unique $child_temp_file in $child_temp_dir.
	    if ($^O eq 'openbsd') {
		(my $fh, $child_temp_file) = mkstemp ("$child_temp_dir/child.XXXXXXXX");
	    }
	    else {
		(my $fh, $child_temp_file) = tempfile ("$child_temp_dir/child.XXXXXXXX");
	    }
	    $child_temp_file = File::Basename::basename ($child_temp_file);
	    # Use temp file for location of changedfile.
	    $changedfile = new ChangedFile ("$child_temp_dir/$child_temp_file", 1);
	    unless ($changedfile) {
		die "Failed to create temp changed file in child: $child_temp_dir/$child_temp_file\n";
	    }
	}
	
	$tree_spec_name = path_to_spec ($tree);
	if ((!$use_privsep && !-e "$spec_dir/$tree_spec_name") ||
	    ($use_privsep && !grep { $_ eq $tree_spec_name } @EXISTING_SPECS)) {
	    print "\n" if ($verbose);
	    print "Warning: Specification for tree $tree doesn't exist. You need to initialize it. Skipping.\n";
	}
	elsif ($subtree_only || $config->tree_uses_sets ($tree, @sets)) {
	    if ($verbose &&
		(!$specs_only || $use_pgp) &&
		(!$no_macos_app_contents || $tree !~ /$MACOS_APP_CONTENTS/)) {
		print "\n$tree";
		print ": start child" if ($fork_children);
		print "\n";
	    }

	    if ($use_pgp) {
		sigtree_verify ("$spec_dir/$tree_spec_name");
	    }
	    if (!$specs_only) {
		check_tree ($config, $TREE_ROOT, $tree, $path, '', $changedfile, "$spec_dir/$tree_spec_name");
		$changedfile->add_time ($tree);
	    }
	}

	if ($fork_children) {
	    # Store the changedfile.
	    eval {
		$changedfile->store_changedfile;
	    };
	    if ($@) {
		warn "FATAL: Child $tree failed to store changed file: $@\n";
		$pm->finish (1); # Exit with error code.
	    }
	    # Verify file was written.
	    unless (-e "$child_temp_dir/$child_temp_file" && -r "$child_temp_dir/$child_temp_file") {
		warn "FATAL: Child $tree changed file missing or unreadable.\n";
		$pm->finish (1);
	    }

	    # debug this seems dumb
	    if ($main::debug_flag) {
		warn "DEBUG: [PID $$] About to call pm->finish for tree $tree\n";
		if ($use_privsep) {
		    my $sock_fd = fileno($FileAttr::PRIV_IPC);
		    warn "DEBUG: [PID $$] Socket fd=$sock_fd\n";
		}
	    }
	    
	    # Report child finish if verbose.
	    print "$tree: finish child" if ($verbose);
	    print " (stored $child_temp_file)" if ($verbose && $main::debug_flag);
	    print "\n" if ($verbose);
	    # Return the filename.
	    $pm->finish (0, \$child_temp_file);
	}
    }

    if ($fork_children) {
	# Wait for all children to finish.
	$pm->wait_all_children;
	# Remove $child_temp_dir.
	remove_temp_dir ($child_temp_dir);
    }

    # Only if a failed worker cannot be matched to a tree (it should
    # always be) is the changed file left as it was.
    if (@failed_trees) {
	my %known = map { $_ => 1 } @specified_trees;
	if (grep { !$known{$_} } @failed_trees) {
	    show_change_details ($changedfile, $verbose, 0, $no_macos_app_contents);
	    die "Check failed for " . scalar (@failed_trees) . " tree(s): @failed_trees\n" .
		"The changed file was not updated; it still holds the previous check's results.\n";
	}
	# A failed tree's results from the previous check are kept.
	delete ($covered{$_}) foreach (@failed_trees);
    }

    # Add the previous check's records for what this check did not cover.
    my $carried = $previous_changedfile->copy;
    $carried->keep_only (sub {
	my ($tree, $full_path) = @_;
	return 0 if ($tree eq $spec_dir);
	return 1 unless (exists ($covered{$tree}));
	return 0 if ($covered{$tree} eq '.');
	# Joined as ChangedFile::add joins them.
	my $checked = "$tree/$covered{$tree}";
	return !($full_path eq $checked || index ($full_path, "$checked/") == 0);
    });
    # The check times are in the new changed file already (they are not
    # reset).
    $carried->{TIME} = {};
    $carried->{USER} = {};
    $changedfile->merge ($carried);

    if (@failed_trees) {
	show_change_details ($changedfile, $verbose, 1, $no_macos_app_contents);
	die "Check failed for " . scalar (@failed_trees) . " tree(s): @failed_trees\n" .
	    "The changed file holds this check's results for the other trees, and the\n" .
	    "previous check's results for these.\n";
    }

    show_change_details ($changedfile, $verbose, 1, $no_macos_app_contents);
}

# Subroutine to show details of the changed file.  Used by check and changes -v.
# The verbose flag argument and the write flag argument are both used by check.
sub show_change_details {
    my ($changedfile, $verbose, $write_flag, $no_macos_app_contents) = @_;
    my ($total_changes, $total_additions, $total_deletions, @changed_sets,
	$priority, $description,
	$changes, $additions, $deletions, @paths, $path, @attrs, $attr);

    ($total_changes, $total_additions, $total_deletions, @changed_sets) = $changedfile->get_sets;

    if ($total_changes == 0 && $total_additions == 0 && $total_deletions == 0) {
	print "\n" if ($verbose);
	print "No changes found.\n";
	# Store it empty: the changed file always exists after a check,
	# and its mtime is the time of the check.
	$changedfile->store_changedfile if ($write_flag);
    }
    else {
	print "\n" if ($verbose);
	print "Priority Set          Changed Added   Deleted Description\n";
	foreach $set (@changed_sets) {
	    ($priority, $description, $changes, $additions, $deletions) = $changedfile->get_set_info ($set);
	    printf "%-8s %-12s %-7s %-7s %-7s %s\n", $priority, $set, $changes, $additions, $deletions, $description;
	}
	printf "TOTAL                 %-7s %-7s %-7s\n", $total_changes, $total_additions, $total_deletions;
	print "\nChanged Objects:";
	foreach $set (@changed_sets) {
	    # With -m, paths inside each macOS app, counted.
	    my %apps;
	    ($priority, $description, $changes, $additions, $deletions) = $changedfile->get_set_info ($set);
	    print "\n$description (set $set, priority $priority)\n";
	    print "Changes: $changes, Additions: $additions, Deletions: $deletions\n";
	    if ($changes > 0) {
		# Each changed path with the spec's value and the value found
		# for each changed attribute (or only their names, from a
		# changed file from before 1.31), and only those -k names.
		# The lists are parallel; before 1.31 a path left out by -m
		# put the rest of the attributes out of step.
		my (@values, @lines, $hidden, $app);
		@paths = $changedfile->get_set_changes ($set);
		@attrs = $changedfile->get_set_changed_attrs ($set);
		@values = $changedfile->get_set_changed_values ($set);
		$hidden = 0;
		foreach my $i (0 .. $#paths) {
		    if ($no_macos_app_contents && defined ($app = _macos_app ($paths[$i]))) {
			$apps{$app}{'changed'}++;
			next;
		    }
		    my $shown = _change_summary ([ split (/,/, $attrs[$i] // '') ], $values[$i]);
		    if (!defined ($shown)) {
			$hidden++;
			next;
		    }
		    push (@lines, "   " . AttrDisplay::esc ($paths[$i]) . " ($shown)\n");
		}
		print "Changes:\n", @lines if (@lines || $hidden);
		print "   ($hidden more changed only in attributes -k leaves out)\n" if ($hidden);
	    }
	    if ($additions > 0) {
		my @lines;
		@paths = $changedfile->get_set_additions ($set);
		foreach $path (@paths) {
		    if ($no_macos_app_contents && defined (my $app = _macos_app ($path))) {
			$apps{$app}{'added'}++;
		    }
		    else {
			push (@lines, "   " . AttrDisplay::esc ($path) . "\n");
		    }
		}
		print "Additions:\n", @lines if (@lines);
	    }
	    if ($deletions > 0) {
		my @lines;
		@paths = $changedfile->get_set_deletions ($set);
		foreach $path (@paths) {
		    if ($no_macos_app_contents && defined (my $app = _macos_app ($path))) {
			$apps{$app}{'deleted'}++;
		    }
		    else {
			push (@lines, "   " . AttrDisplay::esc ($path) . "\n");
		    }
		}
		print "Deletions:\n", @lines if (@lines);
	    }
	    print map { "$_\n" } _macos_app_lines (\%apps);
	}

	# Save list of changed items.
	$changedfile->store_changedfile if ($write_flag);
    }
}

# Subroutine to check trees.  If first arg is $TREE_ROOT, then
# it's the primary invocation, and we have to read the spec_path
# at the beginning and write out the changed file at the end.
# Otherwise, we're in a recursive invocation and we're checking
# files and building the changed file.
sub check_tree {
    my ($config, $tree_root, $tree, $path, $spec, $changedfile, $spec_path) = @_;
    my ($fileattr, $fileattr2, $host, $time, $user, $primary_set,
	$description, $keywords, $priority, %priorities, $file, $full_path, %differences);
    my ($macos_OK_flag);

    return if ($config->path_is_ignored ($tree, $path));

    if ($tree_root) {
	($spec, $fileattr) = new Spec ($tree, $spec_path);
	unless ($spec && $fileattr) {
	    print "Failed to load spec for $tree, skipping.\n";
	    return;
	}
	if ($verbose) {
	    ($host, $time, $user) = $spec->get_info;
	    $time = localtime ($time);
	    print "   Specification for tree $tree created on $time on $host by $user.\n";
	}
	# We may be starting with a subtree.
	if ($path ne '.') {
	    $fileattr = $spec->get ($path);
	}
    }
    else {
	$fileattr = $spec->get ($path);
    }
    $fileattr2 = new FileAttr ($tree, $path, $config->path_sha_digest ($tree, $path));

    if ($tree eq $spec_dir) {
	$primary_set = 'sigtree';
    }
    else {
        $primary_set = $config->primary_set_for_path ($tree, $path);
    }

    # With -m, changes inside a macOS app are not shown one by one; the
    # summary counts them per app. (The full path: the tree itself may
    # be an app, or inside one.)
    $macos_OK_flag = (!$no_macos_app_contents ||
		      !defined (_macos_app (($path eq '.') ? $tree : "$tree/$path")));

    ($description, $keywords, $priority) = $config->set_info ($primary_set);

    %differences = $fileattr->compare ($fileattr2, $keywords);

    if ($differences{'any'}) {
	$changedfile->add ($tree, $path, $primary_set, $fileattr, %differences);

	$fileattr->display_diffs ($primary_set, $priority, %differences) if ($verbose && $macos_OK_flag);
    }
    elsif ($differences{'mtimestasis'}) { # special case for where only change is a noticeable lack of change.
	$fileattr->display_diffs ($primary_set, $priority, %differences) if ($verbose && $macos_OK_flag);
    }

    # Deleted files are a special case.  We walk through them.  (Which
    # means we walk both the old tree structure and the new tree
    # structure.
    if ($differences{'deleted_files'}) {
	foreach $file (@{$differences{'deleted_files'}}) {
	    # Relative to the tree. (By $path, not $tree_root: check_file
	    # can start at a directory below the tree's root.)
	    $full_path = ($path eq '.') ? $file : $path . '/' . $file;
            check_tree ($config, $SUBTREE, $tree, $full_path, $spec, $changedfile);
	}
    }

    if ($fileattr2->{TYPE} eq 'dir') {
	# Read the entries' flags in batches rather than one ls each.
	FileAttr::prefetch_flags ($tree, map { ($path eq '.') ? $_ : "$path/$_" } @{$fileattr2->{FILES}});
        foreach $file (@{$fileattr2->{FILES}}) {
	    $full_path = ($path eq '.') ? $file : $path . '/' . $file;
            check_tree ($config, $SUBTREE, $tree, $full_path, $spec, $changedfile);
        }
    }
}

# Subroutine to update sets.  We update all trees which contain
# any references to the sets specified, so long as there is a
# changed file in existence for that tree.  We update everything
# we find in that tree, regardless of whether there are particular
# exceptions.
sub update_sets {
    my ($config, @sets) = @_;
    my ($changedfile, @changed_trees, $tree, @config_trees, $removed_old_trees,
	$something_to_update, $pgp_passphrase, $tree_spec_name,
	@times, $time, @users, $user, @changed_paths, $changed_path,
	$spec, $fileattr, $fileattr2, $full_path, $path, $primary_set, $description,
	$keywords, $priority, %differences);
    my ($macos_OK_flag);
    my @failed_trees; # Trees whose spec could not be loaded.

    $changedfile = new ChangedFile ($changed_file);
    unless ($changedfile) {
	die "Failed to load changed file: $changed_file\n";
    }

    @changed_trees = $changedfile->get_trees;
    $something_to_update = 0;

    @config_trees = $config->all_trees;
    $removed_old_trees = 0;

    foreach $tree (@changed_trees) {
	if ($tree eq $spec_dir) {
	    @changed_paths = $changedfile->get_paths ($tree);

	    print "Warning: There have been changes to the specification dir itself.\n";
	    print "Please re-initialize all affected trees to create accurate specifications and remove any extraneous files.\n";
	    print "Run sigtree with the check_specs command (or just check again),\n";
	    print "preferably with the -v (verbose) option, to see the detailed list of\n";
	    print "changes to the specification dir.\n";
	    print "The changed specification or extraneous files are:\n";
	    # Why is there a blank first element in the array?
	    foreach $changed_path (@changed_paths) {
		$changed_path =~ s/^\.//;
		print "   " . AttrDisplay::esc ($changed_path) . "\n" if ($changed_path ne '');
	    }
	    # Instead of aborting, why not continue to update these?	    
	    #	    return;
	    print "Will attempt to update all changed trees.\n";
	    $something_to_update = 1;
	    # Need to remove the spec dir from the list, but do it after other changes,
	    # not here.
	}
	elsif (!grep { $_ eq $tree } @config_trees) {
	    print "Warning: changed file contains tree \"$tree\" which is not in config. Removing from changed file.\n";
	    $changedfile->delete ($tree);
	    # Save changes (deletions).
	    $changedfile->store_changedfile;
	    # And delete the changed file if it's now empty.
	    $changedfile->delete_if_empty;
	    $removed_old_trees = 1;
	}
	# No "last" here: every tree is looked at, so that trees no longer
	# in the config are always removed (before 1.31 they were missed if
	# a tree to update came first).
	elsif ($config->tree_uses_sets ($tree, @sets)) {
	    $something_to_update = 1;
	}
    }
    if (!$something_to_update) {
	# Not an error: since 1.30 the changed file is kept when empty.
	print "Nothing changed in specified sets to update.\n";
	return;
    }

    $pgp_passphrase = get_pgp_passphrase() if ($use_pgp);
    # Stop now, before any spec is changed, if the passphrase cannot sign.
    check_passphrase ($pgp_passphrase) if ($use_pgp);

    # Ugly hack, but it prevents a problem.
    @changed_trees = $changedfile->get_trees if ($removed_old_trees);

    foreach $tree (@changed_trees) {
	$tree_spec_name = path_to_spec ($tree);
	# Added $tree ne $spec_dir && so $spec_dir doesn't get treated as regular tree.
	# $spec_dir is initialized separately below.
	# This means changes to spec dir don't get updated, and they are in
	# the changed_file. (But why wasn't it found above and handled?)
	if ($tree ne $spec_dir && $config->tree_uses_sets ($tree, @sets)) {
	    if ($use_privsep && $use_immutable) {
		PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, $spec_dir, $IMMUTABLE_OFF);
		PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, "$spec_dir/$tree_spec_name", $IMMUTABLE_OFF);
		if ($use_pgp) {
		    PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, "$spec_dir/$tree_spec_name.sig", $IMMUTABLE_OFF);
		}
	    }
	    elsif ($use_immutable) {
		set_immutable_flag ($spec_dir, $IMMUTABLE_OFF);
		set_immutable_flag ("$spec_dir/$tree_spec_name", $IMMUTABLE_OFF);
		if ($use_pgp) {
		    set_immutable_flag ("$spec_dir/$tree_spec_name.sig", $IMMUTABLE_OFF);
		}
	    }
	    if ($verbose &&
		(!$no_macos_app_contents || $tree !~ /$MACOS_APP_CONTENTS/)) {
		print "\n$tree\n";
		@times = $changedfile->get_times ($tree);
		@users = $changedfile->get_users ($tree);
		print "This tree was checked and changes were found on:\n";
		foreach $time (@times) {
		    $time = localtime ($time);
		    $user = shift (@users);
		    print "   $time by $user\n";
		}
	    }

	    ($spec, $fileattr) = new Spec ($tree, "$spec_dir/$tree_spec_name");
	    unless ($spec && $fileattr) {
		# Skip only this tree: its changes stay in the changed file,
		# its spec is locked again, and the update goes on (it used
		# to return here, leaving the spec dir unlocked and the spec
		# for the spec dir not regenerated).
		print "Failed to load spec for $tree, skipping.\n";
		push (@failed_trees, $tree);
		if ($use_privsep && $use_immutable) {
		    PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, "$spec_dir/$tree_spec_name", $IMMUTABLE_ON);
		    if ($use_pgp) {
			PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, "$spec_dir/$tree_spec_name.sig", $IMMUTABLE_ON);
		    }
		}
		elsif ($use_immutable) {
		    set_immutable_flag ("$spec_dir/$tree_spec_name", $IMMUTABLE_ON);
		    if ($use_pgp) {
			set_immutable_flag ("$spec_dir/$tree_spec_name.sig", $IMMUTABLE_ON);
		    }
		}
		next;
	    }

	    @changed_paths = $changedfile->get_paths ($tree);
	    # Read the changed paths' flags in batches rather than one ls each.
	    FileAttr::prefetch_flags ($tree, @changed_paths);
	    foreach $changed_path (@changed_paths) {
		if ($changed_path eq '.') {
		    $fileattr2 = new FileAttr ($tree, '.', $config->path_sha_digest ($tree, '.'));
		    $path = $tree;
		    $full_path = $tree;
		}
		else {
		    $fileattr = $spec->get ($changed_path);
		    $fileattr2 = new FileAttr ($tree, $changed_path, $config->path_sha_digest ($tree, $changed_path));
		    $path = $changed_path;
		    $full_path = $tree . '/' . $path;
		}
		$primary_set = $config->primary_set_for_path ($tree, $changed_path);
		($description, $keywords, $priority) = $config->set_info ($primary_set);
		%differences = $fileattr->compare ($fileattr2, $keywords);
		$macos_OK_flag = (!$no_macos_app_contents ||
				  $full_path !~ /$MACOS_APP_CONTENTS/);
		$fileattr->display_diffs ($primary_set, $priority, %differences) if ($verbose && $macos_OK_flag);
		if (!$differences{'any'}) {
		    print "Warning: There are no longer changes to path " . AttrDisplay::esc ($full_path) . ".\n" if ($macos_OK_flag);
		}
		elsif ($differences{'deleted'}) {
		    print "   Deleting " . AttrDisplay::esc ($path) . ".\n" if ($verbose && $macos_OK_flag);
		    $spec->delete ($tree, $changed_path);
		}
		else {
		    if ($differences{'added'} && $differences{'type'} eq 'nonexistent') {
			print "   No change made to spec for " . AttrDisplay::esc ($path) . ".\n" if ($verbose && $macos_OK_flag);
		    }
		    else {
			print "   Adding " . AttrDisplay::esc ($path) . ".\n" if ($verbose && $differences{'added'} && $macos_OK_flag);
			print "   Updating " . AttrDisplay::esc ($path) . ".\n" if ($verbose && !$differences{'added'} && $macos_OK_flag);
			$spec->update ($tree, $changed_path, $fileattr2);
		    }
		}
	    }

	    # Save the changed spec.
	    $spec->store_spec ("$spec_dir/$tree_spec_name");

	    # Sign before removing the tree from the changed file: if
	    # signing fails (dies), the changes stay recorded and a second
	    # update (with the right passphrase) redoes this tree.
	    if ($use_pgp) {
		sigtree_sign ("$spec_dir/$tree_spec_name", $pgp_passphrase);
	    }

	    # Now updated; delete this tree from the changed file.
	    $changedfile->delete ($tree);

	    # Save changes (deletions).
	    $changedfile->store_changedfile;

	    # And delete the changed file if it's now empty.
	    $changedfile->delete_if_empty;
	    if ($use_privsep && $use_immutable) {
		PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, "$spec_dir/$tree_spec_name", $IMMUTABLE_ON);
		if ($use_pgp) {
		    PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, "$spec_dir/$tree_spec_name.sig", $IMMUTABLE_ON);
		}
	    }
	    elsif ($use_immutable) {
		set_immutable_flag ("$spec_dir/$tree_spec_name", $IMMUTABLE_ON);
		if ($use_pgp) {
		    set_immutable_flag ("$spec_dir/$tree_spec_name.sig", $IMMUTABLE_ON);
		}
	    }
	}
    }
    # This will always get hit if there are changes to the spec_dir, since
    # we skipped it above.
    if ((!$use_privsep && -e $changed_file) ||
	($use_privsep && grep { $_ eq $changed_file } @EXISTING_SPECS)) {	
	@changed_trees = $changedfile->get_trees;
	# Filter out spec_dir.
	@changed_trees = grep { $_ ne $spec_dir } @changed_trees;
	
	if ($verbose && @changed_trees) {
	    print "There are still changed files in other sets to be updated.\n";
	    print "Trees remaining:\n";
	    print "@changed_trees\n";
	}
    }
    print "Updating specification for specification dir.\n" if ($verbose);
    if ($use_privsep && $use_immutable) {
	PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, "$spec_dir_dir/$spec_spec", $IMMUTABLE_OFF);
	if ($use_pgp) {
	    PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, "$spec_dir_dir/$spec_spec.sig", $IMMUTABLE_OFF);
	}
    }
    elsif ($use_immutable) {
	set_immutable_flag ("$spec_dir_dir/$spec_spec", $IMMUTABLE_OFF);
	if ($use_pgp) {
	    set_immutable_flag ("$spec_dir_dir/$spec_spec.sig", $IMMUTABLE_OFF);
	}
    }
    # Update's the same as initialize in this respect.
    # This must be done before the specification for the specification dir
    # is created, since changing flags involves inode modification.
    if ($use_privsep && $use_immutable) {
	PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, $spec_dir, $IMMUTABLE_ON);
    }
    elsif ($use_immutable) {
	set_immutable_flag ($spec_dir, $IMMUTABLE_ON);
    }
    create_tree ($config, $TREE_ROOT, $spec_dir, '', '', "$spec_dir_dir/$spec_spec");
    if ($use_pgp) {
	sigtree_sign ("$spec_dir_dir/$spec_spec", $pgp_passphrase);
    }
    if ($use_privsep && $use_immutable) {
	PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, "$spec_dir_dir/$spec_spec", $IMMUTABLE_ON);
	if ($use_pgp) {
	    PrivSep::request_immutable_set ($FileAttr::PRIV_IPC, "$spec_dir_dir/$spec_spec.sig", $IMMUTABLE_ON);
	}
    }
    elsif ($use_immutable) {
	set_immutable_flag ("$spec_dir_dir/$spec_spec", $IMMUTABLE_ON);
	if ($use_pgp) {
	    set_immutable_flag ("$spec_dir_dir/$spec_spec.sig", $IMMUTABLE_ON);
	}
    }

    if ($changedfile->tree_present ($spec_dir)) {
	$changedfile->delete($spec_dir);
	# Save changes (deletions).
	$changedfile->store_changedfile;
	# And delete the changed file if it's now empty.
	$changedfile->delete_if_empty;
    }

    # Overwrite the passphrase now that signing is done.
    if (defined ($pgp_passphrase)) {
	$pgp_passphrase = "x" x length ($pgp_passphrase);
	$pgp_passphrase = '';
    }

    if (@failed_trees) {
	die "Update skipped " . scalar (@failed_trees) . " tree(s) whose spec could not be loaded: @failed_trees\n" .
	    "Their changes are still in the changed file.\n";
    }
}

# Check for existence of root dir, host spec (and sig), spec dir,
# and changed file.  Check for appropriate readability/writability
# of necessary dirs and files.
#
# initialize - requires write access to root dir, host spec (and sig
#              if using PGP), spec dir, any existing specs (and sigs
#              if using PGP).  Will create any dir not present.
#              It's OK if host spec (and sig) or any other specs
#              do not exist.
# check - requires read access to root dir, host spec (and sig if
#              using PGP), spec dir, any existing specs (and sigs
#              if using PGP), read/write access to changed file.
#              Host spec and all required specs (and their sigs)
#              must exist.
# update - requires write access to root dir, host spec (and sig
#              if using PGP), spec dir, any existing specs (and
#              sigs if using PGP), read/write access to changed file.
#              Host spec and all required specs (and their sigs) must
#              exist, as must the changed file.
# Note: If we need to write to any specs/sigs that already exist,
# and we're storing specs as immutable files, then we assume
# those files are already set immutable, and so we abort if
# the current secure level is too high.  It would be better to
# actually check, but perl's stat/lstat don't return the BSD
# file flags. [This is irrelevant, see immutable_file sub!]
# The same problem will exist for dirs, but in
# those cases we'll just produce the "Operation not permitted"
# error which will occur when we can't do what we need to do.
# Also note: We don't currently actually check for the existence
# or readability or writability of any files except for the host
# specification and signature.  We're currently treating them the
# same way as immutable dirs--we'll produce the appropriate error
# when we get there, rather than checking in advance.  Ditto for
# changed file, except that we do check to see if there's anything
# there for the purposes of update.
sub verify_required_dirs {
    my ($caller) = @_;
    my (@changed_files);

    if (!-e $root_dir) {
	if ($caller == $INITIALIZE) {
	    if (!mkdir ($root_dir, 0755)) {
		die "$! $root_dir\n";
	    }
	    else {
		print "Created root dir $root_dir.\n";
	    }
	}
	else {
	    die "Root dir does not exist or is inaccessible. $root_dir\n";
	}
    }
    elsif (!-r $root_dir) {
	die "Root dir is not readable. $root_dir\n";
    }
    # No longer check for whether $root_dir is writeable since we don't
    # put files directly there anymore.
    if (!-e $spec_dir_dir) {
	if ($caller == $INITIALIZE) {
	    if (!mkdir ($spec_dir_dir, 0700)) {
		die "$! $spec_dir_dir\n";
	    }
	    else {
		print "Created main specification dir $spec_dir_dir.\n";
		chown (0, 0, $spec_dir_dir);
		chmod (0700, $spec_dir_dir)
	    }
	}
	else {
	    die "Main specification dir does not exist or is inaccessible. $spec_dir_dir\n";
	}
    }
    elsif (!-r $spec_dir_dir) {
	die "Main specification dir is not readable. $spec_dir_dir\n";
    }
    elsif ($caller != $CHECK && !-w $spec_dir_dir) {
	die "Main specification dir is not writable. $spec_dir_dir\n";
    }

    if (!-e $spec_dir) {
	if ($caller == $INITIALIZE) {
	    # This will fail if $spec_dir_dir already exists and is
	    # immutable.  So we set $spec_dir_dir mutable, create the
	    # $spec_dir directory, set it immutable, and again set
	    # $spec_dir_dir immutable.  We're just going to turn those
	    # flags back off again in a moment, but this sets up the
	    # directories the way they would have been if already
	    # present.
	    # Note: This will leave the $spec_spec in an incorrect
	    # state, since changing immutable flags changes inodes.
	    # If all goes well, that will be invisible since we'll
	    # shortly be re-initializing the $spec_spec (and re-signing
	    # it if PGP signatures are in use).  But if the directory
	    # creation still fails, then we've created a problem.
	    # UPDATE: Now leaving $spec_dir_dir mutable in all cases
	    # going forward and putting the changed files and spec for
	    # the specification dir in them. This also allows using
	    # rsync to combine sigtree files from multiple hosts in one
	    # directory and, in the future, to provide a way to check
	    # remote hosts or check backups.
	    if ($use_immutable) {
		set_immutable_flag ($spec_dir_dir, $IMMUTABLE_OFF);
	    }

	    if (!mkdir ($spec_dir, 0700)) {
		die "$! $spec_dir\n";
	    }
	    else {
		print "Created host specification dir $spec_dir.\n";
		chown (0, 0, $spec_dir);
		chmod (0700, $spec_dir);
		if ($use_immutable) {
		    set_immutable_flag ($spec_dir, $IMMUTABLE_ON);
		}
	    }
	}
	else {
	    die "Host specification dir does not exist or is inaccessible. $spec_dir\n";
	}
    }
    elsif (!-r $spec_dir) {
	die "Host specification dir is not readable. $spec_dir\n";
    }
    elsif ($caller != $CHECK && !-w $spec_dir) {
	die "Host specification dir is not writable. $spec_dir\n";
    }

    if ($caller == $UPDATE && !-e $changed_file) {
	die "There is no changed file from which to update specifications. Use \"initialize\" instead.\n";
    }
    elsif (!-e $changed_file) {
	# If we're initializing, we need to possibly delete this.
	# That code's in initialize_sets.
    }
    elsif ($caller != $INITIALIZE && !-r $changed_file) {
	die "Host changed file is not readable. $changed_file\n";
    }
    elsif ($caller != $INITIALIZE && !-w $changed_file) {
	die "Host changed file is not writeable. $changed_file\n";
    }

    if (!-e $spec_dir_dir . "/$spec_spec" && $caller != $INITIALIZE) {
	die "Host specification does not exist. $spec_dir_dir/$spec_spec.\n";
    }
    elsif (-e $spec_dir_dir . "/$spec_spec") {
	if (!-r $spec_dir_dir . "/$spec_spec") {
	    die "Host specification is not readable. $spec_dir_dir/$spec_spec.\n";
	}
	elsif ($caller != $CHECK && !-w $spec_dir_dir . "/$spec_spec") {
	    die "Host specification is not writable. $spec_dir_dir/$spec_spec\n";
	}
    }

    # Specs locked with a flag only securelevel 0 or -1 can clear (schg)
    # cannot be rewritten above it, so stop here, before the passphrase
    # prompt and before anything is changed. Before 1.32b this test was
    # the last branch of the chain above, reached only when the host spec
    # did not exist, so update went on and failed at the first chflags
    # (-w does not help: root passes it on an schg file).
    if ($caller != $CHECK && $use_immutable && $SECURELEVEL > 0 &&
	$immutable_flag ne $BSD_USER_IMMUTABLE_FLAG && -e $spec_dir_dir . "/$spec_spec") {
	die "Cannot write to existing host specification when kernel securelevel > 0 " .
	    "(securelevel = $SECURELEVEL; the specs are locked with $immutable_flag, which only\n" .
	    "securelevel 0 or -1 can clear: run this in single-user mode, or at securelevel 0).\n";
    }

    if ($use_pgp) {
	if (!-e $spec_dir_dir . "/$spec_spec.sig") {
	    die "Host specification signature does not exist. $spec_dir_dir/$HOSTNAME.sig.\n"
		if ($caller != $INITIALIZE);
	}
	elsif (!-r $spec_dir_dir . "/$spec_spec.sig") {
	    die "Host specification signature is not readable. $spec_dir_dir/$spec_spec.sig.\n";
	}
	elsif ($caller != $CHECK && !-w $spec_dir_dir . "/$spec_spec.sig") {
	    die "Host specification signature is not writable. $spec_dir_dir/$spec_spec.sig\n";
	}
    }

    # Check for world-readable or group-readable spec files
    # This catches historically created files with insecure permissions
    my @files_to_check;
    
    # Add changed file
    push @files_to_check, $changed_file if -e $changed_file;
    
    # Add spec of specs and its signature
    push @files_to_check, "$spec_dir_dir/$spec_spec" if -e "$spec_dir_dir/$spec_spec";
    push @files_to_check, "$spec_dir_dir/$spec_spec.sig" if $use_pgp && -e "$spec_dir_dir/$spec_spec.sig";
    
    # Add all spec files in spec_dir
    if (-d $spec_dir) {
        opendir(my $dh, $spec_dir);
        if ($dh) {
            my @spec_files = grep { /\.spec$|\.sig$/ } readdir($dh);
            closedir $dh;
            push @files_to_check, map { "$spec_dir/$_" } @spec_files;
        }
    }
    
    my @insecure_files;
    foreach my $file (@files_to_check) {
        my @stat = stat($file);
        if (@stat) {
            my $mode = $stat[2] & 0777;
            if ($mode & 0077) {  # Any group or world permissions
                push @insecure_files, sprintf("%s (%04o)", $file, $mode);
            }
        }
    }
    
    if (@insecure_files) {
        warn "\n" . "="x70 . "\n";
        warn "WARNING: The following files have insecure permissions:\n";
        warn "  $_\n" for @insecure_files;
        warn "\nThese files may contain sensitive path information and should be\n";
        warn "readable only by root (permissions 0600).\n\n";
        
        # Check immutable-specs config setting
        my $immutable_specs = $config->{IMMUTABLE_SPECS} || 0;
        
        if ($use_immutable && $immutable_specs) {
            warn "To fix (with immutable-specs enabled):\n";
            if ($^O eq 'linux') {
                warn "  1. chattr -R -i $spec_dir_dir\n";
                warn "  2. chmod -R 0600 $spec_dir_dir\n";
                warn "  3. chattr -R +i $spec_dir_dir\n";
            } else {
                # BSD (OpenBSD, FreeBSD, etc.)
                warn "  1. chflags -R no$immutable_flag $spec_dir_dir\n";
                warn "  2. chmod -R 0600 $spec_dir_dir\n";
                warn "  3. chflags -R $immutable_flag $spec_dir_dir\n";
            }
        } else {
            warn "To fix:\n";
            warn "  chmod -R 0600 $spec_dir_dir\n";
        }
        warn "="x70 . "\n\n";
    }
}

# Subroutine to display list of extraneous files in the specification dir.
sub display_extraneous_files {
    my ($config, $spec_dir, $verbose) = @_;
    my (@extraneous_files, $file);

    @extraneous_files = $use_privsep ? @EXTRANEOUS_SPECS : _identify_extraneous_files ($config, $spec_dir);
    if ($#extraneous_files >= 0) {
	print "The following extraneous files were found in the specification dir $spec_dir.\n";
	foreach $file (@extraneous_files) {
	    print "   " . AttrDisplay::esc ($file) . "\n";
	}
	print "\n"; # Separator needed whether verbose or not. (Might be an edge case where this should not happen with verbose. check_specs -v?)
    }
    else {
	print "No extraneous files were found.\n\n" if ($verbose);
    }
}

# Subroutine to remove extraneous files from the specification dir.
sub remove_extraneous_files {
    my ($config, $spec_dir_dir, $spec_dir, $verbose, $use_immutable) = @_;
    my (@extraneous_files, $file);

    @extraneous_files = _identify_extraneous_files ($config, $spec_dir);
    if ($#extraneous_files >= 0) {
	if ($use_immutable) {
	    set_immutable_flag ($spec_dir, $IMMUTABLE_OFF);
	}

	foreach $file (@extraneous_files) {
	    if ($use_immutable) {
		set_immutable_flag ("$spec_dir/$file", $IMMUTABLE_OFF);
	    }
	    if (unlink ("$spec_dir/$file")) {
		print "$file removed.\n" if ($verbose);
	    }
	    else {
		print "Unable to remove $spec_dir/$file. $!\n";
	    }
	}
	if ($use_immutable) {
	    set_immutable_flag ($spec_dir, $IMMUTABLE_ON);
	}
    }
    else {
	print "No extraneous files were found.\n" if ($verbose);
    }
}

# Subroutine to identify files in the specification dir that
# are not in the configuration. (Or conversely with the
# nonextranous flag.)
sub _identify_extraneous_files {
    my ($config, $spec_dir, $nonextraneous) = @_;
    my (@files, $file, @trees, $tree, $tree_spec_name,
	$file_in_config, @extraneous_files);

    $nonextraneous = 0 if (!defined ($nonextraneous));

    # While this code *could* look at the specification for the specification
    # dir, instead of reading out the files, that would be a historical
    # snapshot instead of right now.
    if (-r $spec_dir) {
	opendir (my $dir_fh, $spec_dir);
	@files = grep (!/^\.{1,2}$/, readdir ($dir_fh));
	closedir ($dir_fh);
	
	@trees = $config->all_trees;
	
	foreach $file (@files) {
	    $file_in_config = 0;
	    foreach $tree (@trees) {
		$tree_spec_name = path_to_spec ($tree);
		$file_in_config = 1 if ($file eq $tree_spec_name ||
					$file eq "$tree_spec_name.sig");
	    } # trees (config) loop
	    push (@extraneous_files, $file) if (!$file_in_config ^ $nonextraneous);
	} # files (spec_dir) loop
	return (@extraneous_files);
    } # can read dir
    return ();
}

# Subroutine to determine if a file is writable.
sub writable_file {
    my ($file) = @_;
    my ($dir);

    # If using privilege separation, skip the check and just return error
    # on failure of priv open for write.
    return 1 if ($use_privsep);

    if (-w $file && ($SECURELEVEL <= 0 || !immutable_file ($file))) {
	return 1;
    }
    # If file doesn't exist, dir must be writable.  We don't
    # auto-create dirs, so this isn't a recursive function.
    elsif (!-e $file) {
	$dir = File::Basename::dirname ($file);
	if (-w $dir && ($SECURELEVEL <= 0 || !immutable_file ($dir))) {
	    return 1;
	}
	else {
	    return 0;
	}
    }
    else {
	return 0;
    }
}

# Subroutine to determine if a file is immutable.
# Now uses _get_file_flags in FileAttr method directly.
# Could use privs if necessary on that call, but shouldn't
# be.
sub immutable_file {
    my ($full_path) = @_;
    my ($flags, $perms, $nlinks, $uid, $gid, $file);

    $flags = FileAttr::_get_file_flags ($full_path);

    return 0 if ($flags eq '<undefined>' ||
		 $flags eq 'none');

    if ((-e $CHFLAGS) &&
	($flags =~ /$BSD_SYS_IMMUTABLE_FLAG/ ||
	 $flags =~ /$BSD_USER_IMMUTABLE_FLAG/)) {
	return 1;
    }
    elsif ((-e $LSATTR) &&
	   $flags =~ /i/) {
	return 1;
    }

    # If immutable flags aren't supported or aren't found.
    return 0;
}

# Subroutine to ask a yes or no question.
sub yes_or_no {
    my ($query) = @_;
    my ($answer);

    while (1) {
	print "$query";
	$answer = <STDIN>;
	# End of input is "no", rather than asking forever.
	if (!defined ($answer)) {
	    print "\n";
	    return 0;
	}
	chomp ($answer);

	if ($answer eq 'yes' || $answer eq 'y') {
	    return 1;
	}
	elsif ($answer eq 'no' || $answer eq 'n') {
	    return 0;
	}
	else {
	    print "Please answer \"yes\" or \"no\".\n";
	}
    }
}

# Subroutine to set immutable flag. Dies if the command cannot be run or
# fails, or if the flag is still set after clearing it. (The privileged
# parent calls this inside an eval and returns the message to the
# requester.)
sub set_immutable_flag {
    my ($path, $on) = @_;
    my ($flag, $linux, $bsd);

    if (-e $CHFLAGS) {
	$bsd = 1;
    }
    elsif (-e $CHATTR) {
	$linux = 1;
    }
    else {
	print "Warning: Don't know how to set immutable flags on this operating system.\n";
	return;
    }

    if ($on) {
	if ($bsd) {
	    $flag = $immutable_flag;
	}
	elsif ($linux) {
	    $flag = $LINUX_IMMUTABLE_FLAG;
	}
    }
    else {
	if ($bsd) {
	    $flag = "no$immutable_flag";
	}
	elsif ($linux) {
	    $flag = $LINUX_IMMUTABLE_FLAG_OFF;
	}
    }

    if (-e $path) {
	my @cmd;
	if ($bsd) {
	    # -h: act on a symlink itself, never on the file it points to.
	    # chflags otherwise follows a symlink named on its command line.
	    @cmd = ($CHFLAGS, '-h', $flag, $path);
	}
	elsif ($linux && !-l $path) {
	    # chattr refuses symlinks; -f suppresses its own messages, so
	    # a failure is reported below.
	    @cmd = ($CHATTR, '-f', $flag, $path);
	}

	if (@cmd) {
	    system (@cmd);
	    my $status = $?;
	    if ($status != 0) {
		die "Unable to " . ($on ? 'set' : 'reset') . " immutable flag on $path: $cmd[0] " .
		    ($status == -1 ? "could not be run: $!" :
		     ($status & 127) ? 'killed by signal ' . ($status & 127) :
		     'exit ' . ($status >> 8)) . "\n";
	    }
	}

	if (!$on && !writable_file ($path)) {
	    die "Unable to reset immutable flag on $path.\n";
	}
    }
}

# Subroutine to get PGP passphrase.
# Must prompt for password if using GPG (GPG2) and privsep, as privileged
# process has no tty.
sub get_pgp_passphrase {
    my ($pgp_passphrase, $current_tty, $temp_file);

    # Set up signal handler to restore echo on interrupt
    local $SIG{INT} = sub { 
        system ($STTY, 'echo'); 
        die "Interrupted\n"; 
    };

    if ($PGP_or_GPG eq 'PGP' ||
	$PGP_or_GPG eq 'GPG1' ||
	($PGP_or_GPG eq 'GPG' && $main::use_privsep) ||
	$PGP_or_GPG eq 'signify') {
	system ($STTY, '-echo');
	print "$PGP_or_GPG Passphrase: ";
	$pgp_passphrase = <STDIN>;
	print "\n";
	system ($STTY, 'echo');
	die "No passphrase given.\n" if (!defined ($pgp_passphrase));
	chomp ($pgp_passphrase);
	return ($pgp_passphrase);
    }
    elsif ($PGP_or_GPG eq 'GPG') {
	# GPG2 with gpg-agent - only works without privsep (needs TTY)
	# With privsep, fall through to prompt method above
	# To get gpg-agent to do the work and get the passphrase, we sign a temp file.
	$pgp_passphrase = '';
	open (my $outfh, '-|', $TTY);
	$current_tty = <$outfh>;
	close ($outfh);
	chomp ($current_tty) if (defined ($current_tty));
	$ENV{'GPG_TTY'} = $current_tty;
	if ($^O eq 'openbsd') {
	    # OpenBSD::MkTemp's mkstemp returns a file handle we don't need.
	    (my $fh, $temp_file) = mkstemp ('/tmp/sigtree.XXXXXXXX');
	}
	else {
	    (my $fh, $temp_file) = tempfile ("/tmp/sigtree.XXXXXXXX");
	}
	sigtree_sign ($temp_file, $pgp_passphrase); # can no longer skip the wrapper due to privsep case
	$pgp_passphrase = "x" x length ($pgp_passphrase); # overwrite memory
	$pgp_passphrase = '';
	unlink ($temp_file);
	unlink ("$temp_file.sig");
	return ($pgp_passphrase);
    }
    else {
	die "Unexpected value for PGP_or_GPG: $PGP_or_GPG\n";
    }
}

# Remove a worker temp dir made by mkdtemp. A worker that died can
# leave its partial temp file there (and Parallel::ForkManager its own),
# so plain files in it are removed first; the dir is 0700 and ours, so
# nothing else can have been put in it.
sub remove_temp_dir {
    my ($dir) = @_;

    if (opendir (my $dh, $dir)) {
	foreach my $entry (readdir ($dh)) {
	    next if ($entry eq '.' || $entry eq '..');
	    unlink ("$dir/$entry") if (-f "$dir/$entry" && !-l "$dir/$entry");
	}
	closedir ($dh);
    }
    rmdir ($dir) or warn "Could not remove $dir: $!\n";
}

# Subroutine to make sure the passphrase can sign before initialize or
# update changes anything: a mistyped passphrase found only at the
# first spec leaves that spec rewritten but unsigned, and a check run
# before the next update would then see no change to redo. Dies if
# signing a throwaway file fails. (GPG 2 without privsep already signed
# a temp file in get_pgp_passphrase, through gpg-agent.)
sub check_passphrase {
    my ($pgp_passphrase) = @_;

    return if ($PGP_or_GPG eq 'GPG' && !$use_privsep);

    if ($use_privsep) {
	PrivSep::request_check_passphrase ($FileAttr::PRIV_IPC, $pgp_passphrase);
    }
    else {
	sign_test_file ($pgp_passphrase);
    }
}

# Sign a throwaway file in a private temp directory with this process's
# method and key, then remove both. Dies with the reason on failure.
# Used by check_passphrase, and by the privileged parent for it, which
# is why the file is in a directory of its own (no other user can put
# anything in a 0700 mkdtemp directory) rather than directly in /tmp.
sub sign_test_file {
    my ($pgp_passphrase) = @_;

    my $dir = mkdtemp ('/tmp/sigtree.XXXXXXXX') or
	die "Could not create temp dir to check the passphrase: $!\n";
    my $file = "$dir/passphrase-check";
    my $error;
    if (my $fh = safe_open_for_write ($file)) {
	print $fh "sigtree passphrase check\n";
	close ($fh) or $error = "Could not write $file: $!\n";
    }
    else {
	$error = "Could not create $file: $!\n";
    }
    if (!$error) {
	eval {
	    if ($use_signify) {
		sigtree_signify_sign ($file, $pgp_passphrase);
	    }
	    else {
		sigtree_pgp_sign ($file, $pgp_passphrase);
	    }
	};
	$error = $@;
    }
    unlink ($file, "$file.sig");
    rmdir ($dir);
    die "The $PGP_or_GPG passphrase was not accepted (nothing has been changed): $error" if ($error);
    return 1;
}

# Generic wrapper for signing. Dies if the file could not be signed.
# (The privileged parent uses its own $use_signify and key paths; the
# request carries only the file and the passphrase.)
sub sigtree_sign {
    my ($file, $pgp_passphrase) = @_;

    if ($use_privsep) {
	PrivSep::request_sign_file ($FileAttr::PRIV_IPC,
				    $file, $pgp_passphrase);
    }
    elsif ($use_signify) {
	sigtree_signify_sign ($file, $pgp_passphrase);
    }
    else {
	sigtree_pgp_sign ($file, $pgp_passphrase);
    }
}

# Generic wrapper for verification.
sub sigtree_verify {
    my ($file) = @_;

    if ($use_privsep) {
	PrivSep::request_verify_signature ($FileAttr::PRIV_IPC, $file);
    }
    elsif ($use_signify) {
	sigtree_signify_verify ($file);
    }
    else {
	sigtree_pgp_verify ($file);
    }
}

# Create a PGP signature in a detached file and save it.
sub sigtree_pgp_sign {
    my ($file, $pgp_passphrase) = @_;
    my ($signature, $version, @data, @errors);

    if (open (my $fh, '<', $file)) {
	while (<$fh>) {
	    push (@data, $_);
	}
	close ($fh);
    }
    else {
	die "Could not read $file to create $PGP_or_GPG signature. $!\n";
    }

    ($signature, $version) = &PGP::Sign::pgp_sign ($config->{PGPKEYID}, $pgp_passphrase, @data);

    if (!defined ($signature)) {
	@errors = &PGP::Sign::pgp_error;
	die "@errors";
    }

    my $fh = safe_open_for_write ("$file.sig") or
	die "Could not write $file.sig to create $PGP_or_GPG signature. $!\n";
    unless ((print $fh "$signature\n") && close ($fh)) {
	die "Could not write $file.sig to create $PGP_or_GPG signature. $!\n";
    }
}

# Verify a PGP signature.
sub sigtree_pgp_verify {
    my ($file) = @_;
    my ($signer, $signature, $version, @data, @errors);
    # $version is left undefined.

    if (open (my $fh, '<', $file)) {
	while (<$fh>) {
	    push (@data, $_);
	}
	close ($fh);
    }
    else {
	print "Cannot open file $file to verify $PGP_or_GPG signature.\n";
	return;
    }
    if (open (my $fh, '<', "$file.sig")) {
	while (<$fh>) {
	    $signature .= $_;
	}
	close ($fh);
	chop ($signature);
    }
    else {
	print "Cannot open file $file.sig to read $PGP_or_GPG signature.\n";
	return;
    }

    $signer = &PGP::Sign::pgp_verify ($signature, $version, @data);
    if (!defined ($signer)) {
	@errors = &PGP::Sign::pgp_error;
	print @errors;
    }
    elsif (!$signer) {
	print "   Warning: Bad $PGP_or_GPG signature on specification. $file.sig\n";
    }
    else {
	print "   Good $PGP_or_GPG signature from $signer on specification.\n" if ($verbose);
    }
}

# Create a signify signature in a detached file and save it.
# Dies if signing fails (as sigtree_pgp_sign does), so that a wrong
# passphrase stops initialize or update instead of leaving specs whose
# old signatures no longer match.
sub sigtree_signify_sign {
    my ($file, $signify_passphrase) = @_;
    my (@errors);
    my $SKIP_SIGNIFY_CHECK = 1;

    if (Signify::sign ($file, { secret_key_path => $signify_seckey,
				passphrase => $signify_passphrase,
				skip_signify_check => $SKIP_SIGNIFY_CHECK })) {
	return 1;
    }

    @errors = Signify::signify_error();
    $errors[0] //= "unknown error\n";

    if ($errors[0] =~ /^no readable file/) {
	die "Could not read $file to create $PGP_or_GPG signature.\n";
    }
    elsif ($errors[0] =~ /^cannot (?:write|create) signature file/) {
	die "Could not write $file.sig to create $PGP_or_GPG signature.\n";
    }
    elsif ($errors[0] =~ /^no readable secret key/) {
	die "Could not read secret key $signify_seckey to create $PGP_or_GPG signature.\n";
    }
    else {
	# signify prints its own reason (e.g. incorrect passphrase) first.
	die "Could not create $PGP_or_GPG signature for $file: @errors";
    }
}

# Verify a signify signature on a specification.
sub sigtree_signify_verify {
    my ($file) = @_;
    my (@errors);
    my $SKIP_SIGNIFY_CHECK = 1;

    if (Signify::verify ($file, { public_key_path => $signify_pubkey,
				  skip_signify_check => $SKIP_SIGNIFY_CHECK })) {
	print "   Good $PGP_or_GPG signature from $signify_pubkey on specification.\n" if ($verbose);
	return;
    }

    @errors = &Signify::signify_error;

    # Report any errors, apart from readability of file itself.
    if ($errors[0] =~ /^no readable signature file/) {
	print "Cannot open file $file.sig to read $PGP_or_GPG signature.\n";
    }
    elsif ($errors[0] =~ /^no readable public key/) {
	print "Cannot open public key $signify_pubkey to verify $PGP_or_GPG signature.\n";
    }
    elsif ($errors[0] =~ /^no readable file/) {
	print "Cannot open file $file to verify $PGP_or_GPG signature.\n";
    }
    else {
	print "   Warning: Bad $PGP_or_GPG signature on specification. $file.sig\n";
	print "   @errors" if ($verbose);
    }
    return;
}

# Subroutine to convert pathname to a specification name by
# converting slashes to periods.
sub path_to_spec {
    my ($string) = @_;

    $string =~ s/^\///g;
    $string =~ s/\//./g;

    return ($string);
}

# Helper to open a file for writing with symlink protection
# Used across packages (Spec::store_spec, ChangedFile::store_changedfile)
# Returns filehandle on success, undef on failure (caller checks $!)
sub safe_open_for_write {
    my ($path, $needs_lock) = @_;
    my $fh;
    unless (sysopen($fh, $path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW)) {
        return undef;
    }
    if ($needs_lock) {
        unless (flock($fh, LOCK_EX)) {
            my $saved_errno = $!;
            close $fh;
            $! = $saved_errno;
            return undef;
        }
    }
    return $fh;
}

### Privilege separation subroutines (main program, also see separate PrivSep package below).

###############################################################################
# PRIVILEGE SEPARATION SETUP
###############################################################################
sub setup_privsep_per_worker {
    my ($num_workers) = @_;
    
    # We need to create socketpairs BEFORE forking privileged parent
    # Create one for each worker PLUS one for main unprivileged parent
    my @parent_socks;
    my @worker_socks;
    my ($main_parent_sock, $main_worker_sock);
    
    # Main process socket (for managing spec files, immutable flags, etc.)
    socketpair($main_parent_sock, $main_worker_sock,
              AF_UNIX, SOCK_STREAM, PF_UNSPEC)
        or die "socketpair for main: $!";
    
    $main_parent_sock->autoflush(1);
    $main_worker_sock->autoflush(1);
    
    # Worker sockets (for file scanning) - only if needed
    if ($num_workers > 0) {
	for my $i (0..$num_workers-1) {
	    socketpair(my $parent_sock, my $worker_sock,
		       AF_UNIX, SOCK_STREAM, PF_UNSPEC)
		or die "socketpair $i: $!";
        
	    $parent_sock->autoflush(1);
	    $worker_sock->autoflush(1);
        
	    push @parent_socks, $parent_sock;
	    push @worker_socks, $worker_sock;
	}
    }
    
    # Fork the privileged parent
    my $priv_pid = fork();
    die "fork privileged parent: $!" unless defined $priv_pid;
    
    if ($priv_pid == 0) {
        # PRIVILEGED PARENT PROCESS (but actually child of main)
        # This process stays as root
	$0 = 'sigtree [priv]';
        
        # Close worker ends (we don't need them)
        close $main_worker_sock;
        close $_ for @worker_socks;

	if ($use_pgp) {
	    # Configure GPG for non-interactive mode in privileged parent
	    # The gpg-noagent wrapper adds --batch --no-tty --pinentry-mode loopback
	    # which allows GPG to accept passphrase programmatically without TTY access
	    $PGP::Sign::PGPS = $PGP::Sign::PGPS; # Avoid "used only once" warning
	    $PGP::Sign::PGPS = $GPG_NOAGENT;
	}

	if ($^O eq 'openbsd') {
	    # Re-pledge, removing @UNVEIL_PROMISE, @PRIVSEP_NONPRIV_PROMISES,
	    # and @PRIVSEP_DROPPRIV_PROMISES.
	    my @promises = (@READONLY_PROMISES, @READWRITE_PROMISES,
			    @CHANGE_ATTR_PROMISES, @EXEC_PROMISES,
			    @FLOCK_PROMISE, @PRIVSEP_PRIV_PROMISES);
	    # stdio is automatically included
	    # If command is "changes", the privileged parent is still needed
	    # but can be read-only--no need to write files, change attributes,
	    # flock, or execute external commands.
	    if ($command eq 'changes') {
		@promises = (@READONLY_PROMISES, @PRIVSEP_PRIV_PROMISES);
		# Reading flags it is asked for runs ls.
		push (@promises, @EXEC_PROMISES) if (defined ($changes_query));
	    }
	    
	    pledge (@promises) || die "Cannot pledge privileged parent promises. $!\n";
	}
        
        # Run privileged request handler with all parent sockets
        privileged_parent_multiplex ($main_parent_sock, @parent_socks);
        
        # Should never get here unless all workers exit
        exit 0;
    }
    
    # MAIN PROCESS (will drop privileges)
    # Close parent ends (we don't need them)
    close $main_parent_sock;
    close $_ for @parent_socks;

    # Drop privileges NOW.
    # Will fail on macOS with perl 5.34.1 unless patched.
    Privileges::Drop::drop_uidgid ($sigtree_uid, $sigtree_gid);
    
    # Return privileged parent PID, worker sockets, and main socket
    return ($priv_pid, \@worker_socks, $main_worker_sock);
}

# Subroutine for privileged parent.
sub privileged_parent_multiplex {
    my (@socks) = @_;
    
    print "DEBUG: [PRIVILEGED PARENT] Starting with " . scalar(@socks) . " channels\n" if ($main::debug_flag);
    print "DEBUG: [PRIVILEGED PARENT] (1 main + " . (scalar(@socks)-1) . " workers)\n" if ($main::debug_flag);
    
    my $select = IO::Select->new(@socks);
    my $request_count = 0;

    # Main loop: wait for requests from any worker
    while (my @ready = $select->can_read()) {
        
        for my $sock (@ready) {
            my $request = PrivSep::recv_request($sock);
            
            if (!$request) {
                # Worker closed its socket (exited)
                print "[PRIVILEGED PARENT] Channel disconnected\n" if ($main::debug_flag);
                $select->remove($sock);
                close $sock;
                next;
            }
            
            $request_count++;
	    
            # Handle the privileged request
            my $response = handle_privileged_request($request);

	    # DEBUG: Show what we're sending and to whom
	    if ($main::debug_flag) {
		warn "[PRIV] [PID $$] Sending response to socket fd " . fileno($sock) . 
		    " for request type=$request->{type} path=" . ($request->{path} || 'none') . "\n";
		warn "[PRIV] [PID $$] Response: success=" . ($response->{success} || 'none') . 
		    " error=" . ($response->{error} || 'none') . "\n";
	    }

	    # If response includes a filehandle, take it and delete
	    # it from the response.
	    my ($response_filehandle, $response_fd_to_send);
	    $response_fd_to_send = undef;
	    if ($response->{_filehandle}) {
		$response_filehandle = $response->{_filehandle};
		$response_fd_to_send = $response->{_fd_to_send};
		delete $response->{_filehandle};
		delete $response->{_fd_to_send};
	    }
            
            # Send response back to the SAME socket
            PrivSep::send_response($sock, $response);
            
            # If response includes a file descriptor to send, send it now
            if (defined $response_fd_to_send) {
		# No ACK is needed before sending the descriptor (the Linux-only
		# ACK was removed in 1.26): every read on these sockets is an
		# exact-length sysread, so the child's read of the response
		# cannot consume the descriptor's carrier byte.
		my $sent;
		{
		    local $SIG{PIPE} = 'IGNORE'; # as in send_response
		    $sent = IO::FDPass::send (fileno ($sock), $response_fd_to_send);
		}
		unless ($sent) {
		    warn "[PRIVILEGED PARENT] Failed to send file descriptor: $!\n";
		}

		# Close our copy of the filehandle (child now has it)
		close $response_filehandle;
	    }
	}

        # Exit when all workers have disconnected
        last unless $select->count();
    }

    print "DEBUG: [PRIVILEGED PARENT] Handled $request_count requests. Exiting.\n" if ($main::debug_flag);
}

sub handle_privileged_request {
    my ($request) = @_;
    
    my $type = $request->{type} // "";
    my $path = $request->{path} // ""; # CHECK_PASSPHRASE has no path

    my @TREE_REQUESTS = ('OPEN', 'STAT', 'READDIR', 'READLINK',
			 'IMMUTABLE_GET');
    my @SIGTREE_FILE_REQUESTS = ('IMMUTABLE_SET', 'DELETE_FILE',
				 'SIGN_FILE', 'VERIFY_SIGNATURE');

    print "DEBUG: [PRIVILEGED PARENT] Received request $type $path\n" if ($main::debug_flag);

    # Validate path for all tree requests OR sigtree file requests.
    if (grep { $_ eq $type } @TREE_REQUESTS) {
	# sigtree's own files in $spec_dir_dir (host spec, changed
	# file, their sigs) are outside the trees and the root dir when
	# an absolute -d puts the spec dir elsewhere.
	unless (is_allowed_path($path) || is_sigtree_managed_file($path)) {
	    return { error => "Path not in allowed trees: $path" };
	}
    }

    # Validate path for all sigtree file requests.
    if (grep { $_ eq $type } @SIGTREE_FILE_REQUESTS) {
	unless (is_sigtree_managed_file($path)) {
	    return { error => "Not a sigtree-managed file: $path" };
	}
    }
    
    if ($type eq 'OPEN') {
        return handle_open_request($request);
    }
    elsif ($type eq 'STAT') {
        return handle_stat_request($request);
    }
    elsif ($type eq 'READDIR') {
        return handle_readdir_request($request);
    }
    elsif ($type eq 'READLINK') {
        return handle_readlink_request($request);
    }
    elsif ($type eq 'IMMUTABLE_GET') {
        return handle_immutable_get_request($request);
    }
    elsif ($type eq 'IMMUTABLE_SET') {
        return handle_immutable_set_request($request);
    }
    elsif ($type eq 'DELETE_FILE') {
        return handle_delete_file_request($request);
    }
    elsif ($type eq 'SIGN_FILE') {
        return handle_sign_file_request($request);
    }
    elsif ($type eq 'VERIFY_SIGNATURE') {
        return handle_verify_signature_request($request);
    }
    elsif ($type eq 'CHECK_PASSPHRASE') {
        # No path: signs a file of its own in a private temp dir.
        return handle_check_passphrase_request($request);
    }
    else {
        return { error => "Unknown request type: $type" };
    }
}

# Privileged read for any file in trees or sigtree-managed files,
# write for sigtree-managed files
sub handle_open_request {
    my ($request) = @_;
    my ($fh);
    my $path = $request->{path};
    my $mode = $request->{mode} || '<'; # Default to read

    # Validate mode
    unless ($mode eq '<' || $mode eq '>') {
	return { error => "Invalid mode: $mode (only '<' or '>' allowed)" };
    }

    # For write mode, validate it's a sigtree-managed file
    if ($mode eq '>') {
	unless (is_sigtree_managed_file($path)) {
	    return { error => "Not a sigtree-managed file: $path" };
	}
    }
    
    # Open file as root using sysopen.
    # For writes and reads, use O_NOFOLLOW to prevent symlink-based
    # attacks.
    my $flags;
    if ($mode eq '>') {
	$flags = O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW;
    }
    else {
        # O_NOFOLLOW: refuse if the final component is now a symlink.
        # O_NONBLOCK: don't hang if the file was swapped for a fifo/device
        #             (no effect on regular files).
	$flags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK;
    }
    unless (sysopen($fh, $path, $flags)) {
	my $err = $!;
	if ($mode eq '>' && ($err == ELOOP || $err == EMLINK)) {
	    return { error => "Refusing to write through symlink: $path ($err)",
		     swap_detected => 1 };
	}
	# ELOOP on Linux/OpenBSD/macOS; EMLINK on FreeBSD for O_NOFOLLOW-on-symlink.
        elsif ($err == ELOOP || $err == EMLINK) {
            return { error => "File type changed between stat and open "
                            . "(now a symlink): $path ($err)",
                     swap_detected => 1 };
        }
        return { error => "$err ($path)" };
    }

    # If the caller told us which inode it stat'd, confirm we opened the
    # same object. Catches what O_NOFOLLOW can't: an intermediate directory
    # component swapped for a symlink, or the file replaced by a different
    # inode (rename-over, hardlink swap, fifo/device).
    if (defined $request->{expect_dev} && defined $request->{expect_ino}) {
        my @st = stat($fh);               # fstat on the open descriptor
        unless (@st) {
            my $e = $!;
            close $fh;
            return { error => "fstat failed after open: $e ($path)" };
        }
        if ($st[0] != $request->{expect_dev} ||
            $st[1] != $request->{expect_ino}) {
            close $fh;
            return { error => "File identity changed between stat and open "
                            . "(dev/ino mismatch): $path",
                     swap_detected => 1 };
        }
    }    
    
    # Get the file descriptor number
    my $fd = fileno($fh);
    # IMPORTANT: We don't include the filehandle in the response
    # because Storable can't serialize it. We just return success
    # and send the FD separately after the response.
    return { 
        success => 1,
        _fd_to_send => $fd,
        _filehandle => $fh,  # Keep handle alive, but won't be serialized
    };
}

sub handle_stat_request {
    my ($request) = @_;
    my $path = $request->{path};
    
    my @stat = lstat($path);
    
    unless (@stat) {
	# errno too, so the requester can tell "not there" from a failure.
        return { error => "$! ($path)", errno => 0 + $! };
    }
    
    return {
        success => 1,
        dev => $stat[0],
        ino => $stat[1],
        mode => $stat[2],
        nlink => $stat[3],
        uid => $stat[4],
        gid => $stat[5],
        rdev => $stat[6],
        size => $stat[7],
        atime => $stat[8],
        mtime => $stat[9],
        ctime => $stat[10],
        blksize => $stat[11],
        blocks => $stat[12],
    };
}

sub handle_readdir_request {
    my ($request) = @_;
    my ($dh);
    my $path = $request->{path};
    
    unless (opendir($dh, $path)) {
        return { error => "$! ($path)" };
    }
    
    my @entries = grep { !/^\.\.?$/ } readdir($dh);
    closedir $dh;

    # Base64 encode each entry to handle non-UTF8 filenames
    my @entries_b64 = map { encode_base64 ($_, '') } @entries;
    
    return {
        success => 1,
        entries => \@entries_b64
    };
}

sub handle_readlink_request {
    my ($request) = @_;
    my $path = $request->{path};
    
    my $target = readlink($path);

    unless (defined $target) {
        return { error => "$! ($path)" };
    }

    # Canonicalize while we have privileges.
    my $canonical_target = FileAttr::_canonicalize_link_target ($path, $target);

    # Get link target file type.
    my @stat = stat ($canonical_target);
    my $mode = $stat[2];
    my $linktarget_type = FileAttr::_get_file_type ($mode);

    # Base64 encode target to handle non-UTF8
    return {
        success => 1,
        target_b64 => encode_base64 ($canonical_target, ''),
	target_type => $linktarget_type
    };
}

# Claude wrote this to use immutable_file, which returns 1 or 0,
# instead of what is actually needed, which is getting the
# actual file flags string.
sub handle_immutable_get_request {
    my ($request) = @_;
    my $path = $request->{path};
    
    my $file_flags = FileAttr::_get_file_flags ($path, 0);
    
    return {
        success => 1,
        flags => $file_flags
    };
}

sub handle_immutable_set_request {
    my ($request) = @_;
    my $path = $request->{path};
    my $immutable = $request->{immutable};

    # set_immutable_flag dies on failure; report it to the requester
    # (which dies with the message) instead of claiming success.
    eval { set_immutable_flag ($path, $immutable); };
    if ($@) {
	return { error => $@ };
    }

    return { success => 1 };
}

sub handle_delete_file_request {
    my ($request) = @_;
    my $path = $request->{path};
    
    unless (unlink($path)) {
        return { error => "Cannot delete: $! ($path)" };
    }
    
    return { success => 1 };
}

sub handle_sign_file_request {
    my ($request) = @_;
    my $file = $request->{path};
    my $pgp_passphrase = $request->{passphrase} // '';

    # Use this process's own signing method and keys (set from the config
    # before the fork), not anything the requester could supply.
    eval {
        if ($main::use_signify) {
            main::sigtree_signify_sign ($file, $pgp_passphrase);
        } else {
            main::sigtree_pgp_sign ($file, $pgp_passphrase);
        }
    };
    my $error = $@;

    # Overwrite this copy of the passphrase.
    $pgp_passphrase = "x" x length ($pgp_passphrase);
    $request->{passphrase} = $pgp_passphrase = '';

    if ($error) {
        return { error => "Signing failed: $error" };
    }
    
    # Ensure .sig file is root-owned
    my $sig_file = "$file.sig";
    if (-e $sig_file) {
        chown(0, 0, $sig_file);
    }
    
    return { success => 1 };
}

# Sign a throwaway file with this process's method and key, so that
# initialize and update can stop on a wrong passphrase before they
# change any spec.
sub handle_check_passphrase_request {
    my ($request) = @_;
    my $pgp_passphrase = $request->{passphrase} // '';

    eval { main::sign_test_file ($pgp_passphrase); };
    my $error = $@;

    # Overwrite this copy of the passphrase.
    $pgp_passphrase = "x" x length ($pgp_passphrase);
    $request->{passphrase} = $pgp_passphrase = '';

    return $error ? { error => $error } : { success => 1 };
}

sub handle_verify_signature_request {
    my ($request) = @_;
    my $file = $request->{path};

    # Call the appropriate verification function, by this process's own
    # setting and public key.
    my $result;
    eval {
        if ($main::use_signify) {
            $result = main::sigtree_signify_verify ($file);
        } else {
            $result = main::sigtree_pgp_verify($file);
        }
    };
    
    if ($@) {
        return { error => "Verification failed: $@" };
    }
    
    return { 
        success => 1,
        verified => $result,
    };
}

sub is_sigtree_managed_file {
    my ($path) = @_;

    # Reject any path containing directory traversal
    # This prevents bypassing tree restrictions via ..
    return 0 if $path =~ m{(?:^|/)\.\.(?:/|\z)};

    # Path must be absolute (no relative paths)
    return 0 unless $path =~ m{^/};

    # Only allow writes to:
    # - Spec files in $spec_dir (per-host)
    # - Spec spec file in $spec_dir_dir
    # - Changed files in $spec_dir_dir (*.changed, *.changedsec)
    # - NOT arbitrary files in $root_dir (no longer used for changed files)
    # (There is deliberately no /tmp exception: nothing under privsep
    # asks the privileged parent to act on a /tmp path, and /tmp is
    # writable by the unprivileged process, which could put a symlink
    # there for chflags or a write to follow.)

    # Check if path is in spec_dir (per-host specs)
    # Restrict to single path component (no subdirectories) using [^/]+
    if (defined $spec_dir) {
        return 1 if $path eq $spec_dir;
	# Individual tree specs have NO extension (e.g., var.www.html)
	# Their signatures have .sig extension
        return 1 if $path =~ m{^\Q$spec_dir\E/[^/]+\z}; # tree spec (no extension)
        return 1 if $path =~ m{^\Q$spec_dir\E/[^/]+\.sig\z}; # tree sig
    }

    # Check if path is in spec_dir_dir (shared parent for multi-host)
    if (defined $spec_dir_dir) {
        # Allow the directory itself
        return 1 if $path eq $spec_dir_dir;

        # Allow spec spec file (e.g., hostname.spec(sec) in spec_dir_dir)
        return 1 if $path =~ m{^\Q$spec_dir_dir\E/[^/]+\.spec\z};
	return 1 if $path =~ m{^\Q$spec_dir_dir\E/[^/]+\.specsec\z};
        return 1 if $path =~ m{^\Q$spec_dir_dir\E/[^/]+\.sig\z};

        # Allow changed files in spec_dir_dir
        return 1 if $path =~ m{^\Q$spec_dir_dir\E/[^/]+\.changed\z};
        return 1 if $path =~ m{^\Q$spec_dir_dir\E/[^/]+\.changedsec\z};
    }

    return 0;
}

# Is it in the configured trees OR in the sigtree files?
sub is_allowed_path {
    my ($path) = @_;
    
    # Path must be absolute
    return 0 unless $path =~ m{^/};

    # Reject any path containing directory traversal, as
    # is_sigtree_managed_file does: otherwise "$tree/../.." reaches any
    # file, and this process reads as root. (Paths sigtree builds itself
    # never contain a .. component: readdir's . and .. are skipped.)
    return 0 if $path =~ m{(?:^|/)\.\.(?:/|\z)};

    # Check against configured trees (loaded from config)
    # Get this from the global $config object
    # Note: This function runs in privileged parent, so it needs
    # access to the tree list. Pass it during setup.

    for my $tree (@ALLOWED_TREES) {
        return 1 if $path =~ m{^\Q$tree\E(?:/|\z)};
    }
    
    return 0;
}

### END Privilege separation subroutines (main program, also see separate PrivSep package below).

### Config package.

# Runs privileged and would require some changes to run unprivileged.

# Methods to handle config file object.
package Config;

use strict;
use warnings;

# Parse a config file, report any errors, create a config object.
# Config file has three sections:
#   1. Section for global attributes (currently crypto_sigs, pgpkeyid, and immutable-specs).
#   2. Section for set definitions.
#   3. Section for list of trees.
sub new {
    my $class = shift;
    my ($config_file) = @_;

    my $GLOBAL_ATTRIBUTES = 0;
    my $SET_DEFINITIONS = 1;
    my $TREES_LIST = 2;

    my @ALL_KEYWORDS = (
			'gid',
			'mode',
	                'nlink',
	                'shadigest',
	                'sha2digest',
	                'sha3digest',
			'uid',
			'size',
			'link',
			'linktarget_type',
			'mtime',
			'ctime',
			'type',
			'ignore',
			'flags',
			'rdev'
			);

    my $DEFAULT_KEYWORDS = 'gid,mode,nlink,shadigest,uid,size,link,mtime,ctime,type,flags';

    my ($self, $state, $line, $raw_line, $field, $value);
    my ($set_long_name, $set_short_name, %used_set_names, %set_has_members,
	$current_set, @keywords, $keyword, $path, $set_list,
	@sets, $set_name, $arg_no, $error, %used_tree_paths, $current_tree,
	%exception_modes, $tree, $other_tree);

    $self->{CRYPTO_SIGS} = 0;
    $self->{PGPKEYRING} = 0;
    $self->{PGPKEYID} = 0;
    $self->{SIGNIFY_SECKEY} = 0;
    $self->{SIGNIFY_PUBKEY} = 0;
    $self->{IMMUTABLE_SPECS} = 0;
    $self->{SHA_DIGEST} = 0;
    $self->{SHA_DIGEST_BITS} = 0;
    $self->{MAX_CHILD_PROCS} = 0;
    $self->{DEFAULT_CHILD_PROCS} = 0;
    $self->{PRIVSEP} = 0;

    bless $self, $class;

    $state = $GLOBAL_ATTRIBUTES;

    $line = 0;

    $current_set = 0;

    open (my $config_fh, '<', $config_file) ||
	die "Cannot open config file. $!. $config_file\n";

    # Verify config file permissions are not world-readable.
    my @stat = stat ($config_fh);
    if (@stat) {
	my $mode = $stat[2] & 07777; # Get permission bits
	my $uid = $stat[4];

	# FATAL: Reject if group or world writable
        if ($mode & 0022) {
            die "Config file $config_file has unsafe write permissions (" . 
                sprintf("%04o", $mode) . "). Must not be group or world writable.\n" .
                "Fix with: chmod go-w $config_file\n";
        }
        
        # FATAL: Reject if not owned by root (or current effective user)
        if ($uid != 0 && $uid != $>) {
            die "Config file $config_file is not owned by root (uid=$uid). " .
                "Fix with: chown root $config_file\n";
        }
        
        # WARN: Group or world readable
        if ($mode & 0044) {
            warn "WARNING: Config file $config_file is " .
                 (($mode & 0004) ? "world" : "group") . "-readable (permissions: " .
                 sprintf("%04o", $mode) . "). Consider chmod 0600 $config_file\n";
        }
    }
    while (<$config_fh>) {
	$line++;
	$raw_line = $_;
	chop;
	s/^\s+//;
	if (!/^#|^$/) {
	    if (!/:/) {
		die "Unparseable statement, line $line. $config_file\nLine: $raw_line";
	    }
	    ($field, $value) = split (/:\s*/, $_, 2);
	    if ($field eq 'crypto_sigs') {
		if ($state != $GLOBAL_ATTRIBUTES) {
		    die "A \"crypto_sigs:\" field in wrong section, line $line. $config_file\nLine: $raw_line";
		}
		if ($self->{CRYPTO_SIGS}) {
		    die "A second \"crypto_sigs:\" field, line $line. $config_file\nLine: $raw_line";
		}
		if ($value eq 'none' || $value eq 'PGP' || $value eq 'GPG' || $value eq 'GPG1' || $value eq 'signify') {
		    $self->{CRYPTO_SIGS} = $value;
		}
		else {
		    die "Invalid value \"$value\" for \"crypto_sigs:\" field, on line $line. $config_file\nLine: $raw_line";
		}
	    }
	    elsif ($field eq 'pgpkeyring') {
		if ($state != $GLOBAL_ATTRIBUTES) {
		    die "A \"pgpkeyring:\" field in wrong section, line $line. $config_file\nLine: $raw_line";
		}
		if ($self->{PGPKEYRING}) {
		    die "A second \"pgpkeyring:\" field, line $line. $config_file\nLine: $raw_line";
		}
		if (-r $value) {
		    $self->{PGPKEYRING} = $value;
		}
		else {
		    die "Cannot open \"pgpkeyring:\" file $value for reading.\n";
		}
	    }
	    elsif ($field eq 'pgpkeyid') {
		if ($state != $GLOBAL_ATTRIBUTES) {
		    die "A \"pgpkeyid:\" field in wrong section, line $line. $config_file\nLine: $raw_line";
		}
		if ($self->{PGPKEYID}) {
		    die "A second \"pgpkeyid:\" field, line $line. $config_file\nLine: $raw_line";
		}
		$self->{PGPKEYID} = $value;
	    }
	    elsif ($field eq 'signify_seckey' || $field eq 'signify_pubkey') {
		if ($state != $GLOBAL_ATTRIBUTES) {
		    die "A \"$field:\" field in wrong section, line $line. $config_file\nLine: $raw_line";
		}
		if (($field eq 'signify_seckey' && $self->{SIGNIFY_SECKEY}) ||
		    ($field eq 'signify_pubkey' && $self->{SIGNIFY_PUBKEY})) {
		    die "A second \"$field:\" field, line $line. $config_file\nLine: $raw_line";
		}
		if (!-r $value) {
		    die "Cannot open \"$field:\" file $value for reading.\n";
		}
		elsif ($field eq 'signify_seckey') {
		    $self->{SIGNIFY_SECKEY} = $value;
		}
		else {
		    $self->{SIGNIFY_PUBKEY} = $value;
		}
	    }
	    elsif ($field eq 'immutable-specs') {
		if ($state != $GLOBAL_ATTRIBUTES) {
		    die "An \"immutable-specs:\" field is in the wrong section, line $line. $config_file\nLine: $raw_line";
		}
		if ($self->{IMMUTABLE_SPECS}) {
		    die "A second \"immutable-specs:\" field, line $line. $config_file\nLine: $raw_line";
		}
		if ($value ne 'yes' && $value ne 'no' && $value ne $BSD_SYS_IMMUTABLE_FLAG && $value ne $BSD_USER_IMMUTABLE_FLAG) {
		    die "Invalid value \"$value\" for \"immutable-specs:\" field, on line $line. $config_file\nLine: $raw_line";
		}
		$self->{IMMUTABLE_SPECS} = $value;
	    }
	    elsif ($field eq 'sha2_digest') {
		if ($state != $GLOBAL_ATTRIBUTES) {
		    die "A \"sha2_digest:\" field is in the wrong section, line $line. $config_file\nLine: $raw_line";
		}
		if ($self->{SHA_DIGEST} == $SHA2_DIGEST) {
		    die "A second \"sha2_digest:\" field, line $line. $config_file\nLine: $raw_line";
		}
		if ($self->{SHA_DIGEST} == $SHA3_DIGEST) {
		    die "A \"sha2_digest:\" field has been found in addition to a \"sha3_digest:\" field. $config_file\nLine: $raw_line";
		}
		if ($value ne '256' && $value ne '384' && $value ne '512') {
		    die "Invalid value \"$value\" for \"sha2_digest:\" field, on line $line. $config_file\nLine: $raw_line";
		}
		else {
		    $self->{SHA_DIGEST} = $SHA2_DIGEST;
		    $self->{SHA_DIGEST_BITS} = $value;
		}
	    }
	    elsif ($field eq 'sha3_digest') {
		if ($state != $GLOBAL_ATTRIBUTES) {
		    die "A \"sha3_digest:\" field is in the wrong section, line $line. $config_file\nLine: $raw_line";
		}
		if ($self->{SHA_DIGEST} == $SHA3_DIGEST) {
		    die "A second \"sha3_digest:\" field, line $line. $config_file\nLine: $raw_line";
		}
		if ($self->{SHA_DIGEST} == $SHA2_DIGEST) {
		    die "A \"sha3_digest:\" field has been found in addition to a \"sha2_digest:\" field. $config_file\nLine: $raw_line";
		}
		if ($value ne '224' && $value ne '256' && $value ne '384' && $value ne '512') {
		    die "Invalid value \"$value\" for \"sha2_digest:\" field, on line $line. $config_file\nLine: $raw_line";
		}
		else {
		    $self->{SHA_DIGEST} = $SHA3_DIGEST;
		    $self->{SHA_DIGEST_BITS} = $value;
		}
	    }
	    elsif ($field eq 'max_child_procs') {
		if ($state != $GLOBAL_ATTRIBUTES) {
		    die "A \"max_child_procs:\" field is in the wrong section, line $line. $config_file\nLine: $raw_line";
		}
		if ($self->{MAX_CHILD_PROCS}) {
		    die "A second \"max_child_procs:\" field, line $line. $config_file\nLine: $raw_line";		    
		}
		if ($value =~ /^\d+$/) {
		    die "\"max_child_procs:\" field must be zero or an integer >= 2, line $line. $config_file\nLine: $raw_line" if ($value == 1);	    
		}
		else {
		    die "\"max_child_procs:\" field must be an integer, line $line. $config_file\nLine: $raw_line";
		}
		$self->{MAX_CHILD_PROCS} = $value;
		if ($self->{DEFAULT_CHILD_PROCS} && $self->{DEFAULT_CHILD_PROCS} > $self->{MAX_CHILD_PROCS}) {
		    die "\"max_child_procs:\" field is set to a value lower than \"default_child_procs:\", line $line $config_file\nLine: $raw_line";
		}
	    }
	    elsif ($field eq 'default_child_procs') {
		if ($state != $GLOBAL_ATTRIBUTES) {
		    die "A \"default_child_procs:\" field is in the wrong section, line $line. $config_file\nLine: $raw_line";
		}
		if ($self->{DEFAULT_CHILD_PROCS}) {
		    die "A second \"default_child_procs:\" field, line $line. $config_file\nLine: $raw_line";		    
		}
		if ($value =~ /^\d+$/) {
		    die "\"default_child_procs:\" field must be zero or an integer >= 2, line $line. $config_file\nLine: $raw_line" if ($value == 1);
		}
		else {
		    die "\"default_child_procs:\" field must be an integer, line $line. $config_file\nLine: $raw_line";
		}
		$self->{DEFAULT_CHILD_PROCS} = $value;
		if ($self->{DEFAULT_CHILD_PROCS} && $self->{MAX_CHILD_PROCS} &&
		    $self->{DEFAULT_CHILD_PROCS} > $self->{MAX_CHILD_PROCS}) {
		    die "\"default_child_procs:\" field is set to a value higher than \"max_child_procs:\", line $line $config_file\nLine: $raw_line";
		}	
	    }
	    elsif ($field eq 'privsep') {
		if ($state != $GLOBAL_ATTRIBUTES) {
		    die "A \"privsep:\" field is in the wrong section, line $line. $config_file\nLine: $raw_line";
		}
		if ($self->{PRIVSEP}) {
		    die "A second \"privsep:\" field, line $line. $config_file\nLine: $raw_line";
		}
		if ($value eq 'yes' || $value eq 'no') {
		    $self->{PRIVSEP} = $value;
		}
		else {
		    die "\"privsep:\" field must be \"yes\" or \"no\", line $line. $config_file\nLine: $raw_line";
		}
	    }
	    elsif ($field eq 'set') {
		if ($state != $GLOBAL_ATTRIBUTES &&
		    $state != $SET_DEFINITIONS) {
		    die "A \"set:\" field in wrong section, line $line. $config_file\nLine: $raw_line";
		}
		$state = $SET_DEFINITIONS;
		if ($value !~ /^([\w-]+),([\w-]+)$/) {
		    die "Invalid \"set:\" field syntax, line $line. $config_file\nLine: $raw_line";
		}
		$set_long_name = $1;
		$set_short_name = $2;

		if (length ($set_long_name) > 12) {
		    die "Set name \"$set_long_name\" is longer than the maximum length of 12 characters.\n";
		}
		if (length ($set_short_name) > 12) {
		    die "Set name \"$set_short_name\" is longer than the maximum length of 12 characters.\n";
		}

		if (defined ($used_set_names{$set_long_name})) {
		    die "Set long name \"$set_long_name\" defined a second time, line $line. $config_file\nLine: $raw_line";
		}
		if (defined ($used_set_names{$set_short_name})) {
		    die "Set short name \"$set_short_name\" defined a second time, line $line. $config_file\nLine: $raw_line";
		}

		$used_set_names{$set_long_name} = 1;
		$used_set_names{$set_short_name} = 1;

		$set_has_members{$set_long_name} = 0;

		push (@{$self->{SETS}}, $value);
		${$self->{KEYWORDS}}{$set_long_name} = 0;
		${$self->{PRIORITY}}{$set_long_name} = 0;

                # If no description has been set, complain.
                if ($current_set && !${$self->{DESCRIPTION}}{$current_set}) {
                    die "No \"description:\" field for set \"$current_set\". $config_file\n";
                }

                # If keywords are still 0 for previous current_set, set
                # to the defaults.
                if ($current_set && !${$self->{KEYWORDS}}{$current_set}) {
                    ${$self->{KEYWORDS}}{$current_set} = $DEFAULT_KEYWORDS;
                }

		$current_set = $set_long_name;
	    }
            elsif ($field eq 'description') {
		if ($state != $SET_DEFINITIONS) {
                    die "A \"description:\" field in wrong section, line $line. $config_file\nLine: $raw_line";
                }
                if (${$self->{DESCRIPTION}}{$current_set}) {
		    die "Second \"description:\" field for set \"$current_set\", line $line. $config_file\nLine: $raw_line";
	        }
                ${$self->{DESCRIPTION}}{$current_set} = $value;
            }
	    elsif ($field eq 'keywords') {
		if ($state != $SET_DEFINITIONS) {
		    die "A \"keywords:\" field in wrong section, line $line. $config_file\nLine: $raw_line";
		}
		if (${$self->{KEYWORDS}}{$current_set}) {
		    die "Second \"keywords:\" field for set \"$current_set\", line $line. $config_file\nLine: $raw_line";
	        }
                if ($value !~ /^(?:[\w\d-]+,\s*)+[\w\d-]+$|^[\w\d-]+$/) {
		    die "Invalid \"keywords:\" field for set \"$current_set\", line $line. $config_file\nLine: $raw_line";
		}
		@keywords = split (/,\s*/, $value);
                while ($keyword = pop (@keywords)) {
		    if (!grep (/^$keyword$/, @ALL_KEYWORDS) &&
			$keyword !~ /^mtimestasis-\d{1,2}[smhd]$/) {
			die "Invalid keyword \"$keyword\" for set \"$current_set\", line $line. $config_file\nLine: $raw_line";
		    }
		    elsif (grep (/^$keyword$/, @keywords) ||
			   ($keyword =~ /^mtimestasis-\d{1,2}[smhd]$/ && grep (/^mtimestasis-\d{1,2}[smhd]$/, @keywords))) {
			die "Second \"$keyword\" keyword for set \"$current_set\", line $line. $config_file\nLine: $raw_line";
		    }
                }       

                ${$self->{KEYWORDS}}{$current_set} = $value;
	    }
	    elsif ($field eq 'priority') {
		if ($state != $SET_DEFINITIONS) {
		    die "A \"priority:\" field in wrong section, line $line. $config_file\nLine: $raw_line";
		}
		if (${$self->{PRIORITY}}{$current_set}) {
		    die "Second \"priority:\" field for set \"$current_set\", line $line. $config_file\nLine: $raw_line";
	        }
                if ($value !~ /^\d+$/) {
                    die "Invalid \"priority:\" field for set \"$current_set\", line $line. $config_file\nLine: $raw_line";
                }
                ${$self->{PRIORITY}}{$current_set} = $value;
	    }
	    elsif ($field eq 'tree') {
		if ($state != $SET_DEFINITIONS &&
		    $state != $TREES_LIST) {
		    die "A \"tree:\" field in wrong section, line $line. $config_file\nLine: $raw_line";
		}

                # If keywords are still 0 for previous current_set, set
                # to the defaults.
                if ($current_set && !${$self->{KEYWORDS}}{$current_set}) {
                    ${$self->{KEYWORDS}}{$current_set} = $DEFAULT_KEYWORDS;
                }

		$state = $TREES_LIST;
		if ($value !~ /^.*:([\w-]+,\s*)+[\w-]+$|^.*:[\w-]+$/) {
		    die "Invalid \"tree:\" field, line $line. $config_file\nLine: $raw_line";
		}
		($path, $set_list) = split (/:/, $value);
                ($arg_no, $error, @sets) = $self->valid_setlist ($set_list);
                if ($error == $SET_NAME_INVALID) {
		    die "Invalid set \"$sets[$arg_no]\" in \"tree:\" field, line $line. $config_file\nLine: $raw_line";
                }
                elsif ($error == $SET_UNDEFINED) {
		    die "Undefined set \"$sets[$arg_no]\" in \"tree:\" field, line $line. $config_file\nLine: $raw_line";
                }
                elsif ($error == $SET_REDUNDANT) {
		    die "Second set \"$sets[$arg_no]\" in \"tree:\" field, line $line. $config_file\nLine: $raw_line";
                }
		elsif ($error == $SET_INCLUDES_UNINITIALIZED) {
		    die "Reserved set name \"$sets[$arg_no]\" in \"tree:\" field, line $line. $config_file\nLine: $raw_line";
		}
                foreach $set_name (@sets) {
		    $set_has_members{$set_name} = 1;
                }
		if ($used_tree_paths{$path}) {
		    die "Second \"tree:\" field \"$path\", line $line. $config_file\nLine: $raw_line";
		}
		if (!-e $path) {
		    print "Warning: Path \"$path\" in \"tree:\" field does not exist or is inaccessible, line $line. $config_file\nLine: $raw_line";
		}

		$used_tree_paths{$path} = 1;

		push (@{$self->{TREES}}, $path);
		${$self->{TREE_SETS}}{$path} = _set_array_to_set_list (@sets);

                $current_tree = $path;
	    }
	    elsif ($field =~ /^(primary-|secondary-)?(exception|exception-tree)\z/) {
		# primary-exception: and secondary-exception: (and their -tree
		# forms) apply only to primary specs (any run without
		# "-d secondary") or only to secondary specs, so a path can be
		# in one set for each: a log that must change daily, checked in
		# the secondary specs, may not exist at all in single-user mode,
		# when the primary specs are made. The other mode's lines are
		# checked like any other and then not used.
		my $mode = defined ($1) ? substr ($1, 0, -1) : '';
		my $kind = $2;
		my $an = ($field =~ /^[aeiou]/) ? 'An' : 'A'; # for messages
		my $active = ($mode eq '' ||
			      ($mode eq 'secondary') == ($secondary_specs ? 1 : 0));
		if ($state != $TREES_LIST) {
		    die "$an \"$field:\" field in wrong section, line $line. $config_file\nLine: $raw_line";
		}
		if ($value !~ /^.*:[\w-]+$/) {
		    die "Invalid \"$field:\" field, line $line. $config_file\nLine: $raw_line";
		}
		if (!-d $current_tree) {
		    die "$an \"$field:\" field defined for a non-directory tree \"$current_tree\", line $line. $config_file\nLine: $raw_line";
		}
		($path, $set_list) = split (/:/, $value);
		($arg_no, $error, @sets) = $self->valid_setlist ($set_list);
		if ($error == $SET_NAME_INVALID) {
		    die "Invalid set \"$sets[$arg_no]\" in \"$field:\" field, line $line. $config_file\nLine: $raw_line";
		}
		elsif ($error == $SET_UNDEFINED) {
		    die "Undefined set \"$sets[$arg_no]\" in \"$field:\" field, line $line. $config_file\nLine: $raw_line";
		}
		# Reserved set names "new"/"uninitialized" can be used on command line for initialize command only.
		elsif ($error == $SET_INCLUDES_UNINITIALIZED) {
		    die "Reserved set name \"$sets[$arg_no]\" in \"$field:\" field, line $line. $config_file\nLine: $raw_line";
		}
# Can't occur unless we decide to allow setlists here again for
# some reason.
#		elsif ($error == $SET_REDUNDANT) {
#		    die "Second set \"$sets[$arg_no]\" in \"$field:\" field, line $line. $config_file\nLine: $raw_line";
#		}
		foreach $set_name (@sets) {
		    $set_has_members{$set_name} = 1;
		}
		# One line per path for each mode, and a path is either
		# shared ("exception:") or per mode, not both.
		my $seen = ($exception_modes{"$kind:$current_tree/$path"} //= {});
		if ($seen->{$mode}) {
		    die "Second \"$field:\" field \"$path\" for tree \"$current_tree\", line $line. $config_file\nLine: $raw_line";
		}
		if (($mode eq '' && ($seen->{primary} || $seen->{secondary})) ||
		    ($mode ne '' && $seen->{''})) {
		    die "Path \"$path\" for tree \"$current_tree\" has both \"$kind:\" and \"primary-$kind:\" or \"secondary-$kind:\"; use \"$kind:\" for both kinds of specs, or one line for each, line $line. $config_file\nLine: $raw_line";
		}
		$seen->{$mode} = 1;

		# Exception paths are relative to the tree. An absolute one
		# would be looked up as "$current_tree//abs/path" and never
		# match, silently (no existence warning) if its set ignores it.
		if (substr ($path, 0, 1) eq '/') {
		    my $relative = _relative_hint ($current_tree, $path);
		    # The whole tree as an exception-tree is just the tree's own
		    # set list, so there is no relative form to suggest.
		    $path = $relative if (defined ($relative) && $relative eq '.' && $kind eq 'exception-tree');
		    if ($path ne '.') {
			die "The \"$field:\" path \"$path\" for tree \"$current_tree\" must be relative to the tree" .
			    (defined ($relative) ? " (\"$relative\")" : ", and this one is not in the tree") .
			    ", line $line. $config_file\nLine: $raw_line";
		    }
		}

		# Don't allow ..; . is allowed only for "exception:".
		if ($path eq '..') {
		    die "Cannot use \"$path\" in \"$field:\" field for tree \"$current_tree\", line $line. $config_file\nLine: $raw_line";
		}
		if ($path eq '.' && $kind eq 'exception-tree') {
		    if ($mode ne '') {
			# The tree: line is shared, so there is nothing to point to.
			die "A \"$field:\" for all of tree \"$current_tree\" would give the whole tree different sets in $mode specs, which is not supported; use $mode-exception: or $mode-exception-tree: lines for the paths in it, line $line. $config_file\nLine: $raw_line";
		    }
		    die "An \"$field:\" for all of tree \"$current_tree\" is the same as the tree's own sets; change its \"tree:\" line instead (\"exception: .\" changes only the tree's root directory), line $line. $config_file\nLine: $raw_line";
		}

		# A line for the other kind of specs stops here.
		next unless ($active);

		if ($kind eq 'exception-tree') {
		    $self->{TREE_DIR_EXCEPTION_SETS}->{$current_tree}->{$path} = _set_array_to_set_list (@sets);
		}
		else {
		    $self->{TREE_EXCEPTION_SETS}->{$current_tree}->{$path} = _set_array_to_set_list (@sets);
		}
		# Move the test for directory or existence here, after it's set up, so we can respect the "ignore" keyword.
		if (!$self->path_is_ignored ($current_tree, $path)) {
		    if ($kind eq 'exception-tree' && !-d $current_tree . '/' . $path) {
			print "Warning: Path \"$path\" in \"$field:\" field for tree \"$current_tree\" is not a directory or is inaccessible, line $line. $config_file\nLine: $raw_line";			
		    }
		    elsif ($kind ne 'exception-tree' && !-e $current_tree . '/' . $path) {
			print "Warning: Path \"$path\" in \"$field:\" field for tree \"$current_tree\" does not exist or is inaccessible, line $line. $config_file\nLine: $raw_line";		    
		    }
		}
	    }
	    else {
		die "Invalid field \"$field\", line $line. $config_file\nLine: $raw_line";
	    }
	} # non-comment and non-blank line
    }
    close ($config_fh);

    # If no sha3_digest or sha2_digest field was specified, default
    # is SHA-3, 256 bits.
    $self->{SHA_DIGEST} = $SHA3_DIGEST if ($self->{SHA_DIGEST} == 0);
    $self->{SHA_DIGEST_BITS} = $SHA3_256 if ($self->{SHA_DIGEST_BITS} == 0);

    # If no max_child_procs or default_child_procs set, set to defaults,
    # and if only one or the other is set, make sure default < max, otherwise
    # adjust and warn.
    if ($self->{MAX_CHILD_PROCS} == 0) {
	$self->{MAX_CHILD_PROCS} = $MAX_CHILD_PROCS;
	if ($self->{DEFAULT_CHILD_PROCS} > $MAX_CHILD_PROCS) {
	    print "Warning: your config sets default_child_procs to a value greater than the default for max_child_procs, which is not set in your config. Adjusting max_child_procs to match your config default_child_procs setting.\n";
	    $self->{MAX_CHILD_PROCS} = $self->{DEFAULT_CHILD_PROCS};
	}
    }
    if ($self->{DEFAULT_CHILD_PROCS} == 0) {
	$self->{DEFAULT_CHILD_PROCS} = $DEFAULT_CHILD_PROCS;
	if ($self->{MAX_CHILD_PROCS} < $DEFAULT_CHILD_PROCS) {
	    print "Warning: your config sets max_child_procs to a value lower than the default for default_child_procs, which is not set in your config. Adjusting default_child_procs to match your config max_child_procs setting.\n";
	    $self->{DEFAULT_CHILD_PROCS} = $self->{MAX_CHILD_PROCS};
	}
    }

    # Make sure at least one tree is defined (or abort).
    if (!$current_tree) {
	die "No trees defined. $config_file\n";
    }

    # Make sure no trees are subtrees of other trees.
    foreach $tree (@{$self->{TREES}}) {
	$other_tree = $self->tree_for_path ($tree);
	if ($other_tree && $tree ne $other_tree) {
	    die "Tree $tree is a subtree of $other_tree.\n";
	}
    }

    # Make sure sigtree set is defined.
    if (!$self->defined_set ('sigtree')) {
	die "Special \"sigtree\" set is not defined.\n";
    }

    # Make sure all sets have members (warn otherwise).
    foreach $set_name (keys (%set_has_members)) {
	if (!$set_has_members{$set_name} && ($set_name ne 'sigtree')) {
	    print "Warning: set \"$set_name\" is defined but has no members.\n";
	}
    }

    return $self;
}

# Method used to tell if a given set name has been defined.
sub defined_set {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($set) = @_;
    my ($set_name, $set_long_name, $set_short_name);

    # Undefined set always exists.
    return 1 if (!$set);

    # "new" is a special case.
    return 1 if ($set eq 'new');

    foreach $set_name (@{$self->{SETS}}) {
	($set_long_name, $set_short_name) = split (/,/, $set_name);
	return 1 if ($set_long_name eq $set || $set_short_name eq $set);
    }

    return 0;
}

# Method to return long (primary) name of set.
sub long_name {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($set) = @_;
    my ($set_name, $set_long_name, $set_short_name);

    foreach $set_name (@{$self->{SETS}}) {
	($set_long_name, $set_short_name) = split (/,/, $set_name);
	if ($set eq $set_long_name || $set eq $set_short_name) {
	    return $set_long_name;
	}
    }

    return 0;
}

# Method used to tell if a set list is valid, and return as an array
# of primary (long) set names.
sub valid_setlist {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($set_list) = @_;
    my (@sets, @return_sets, $set_name, $arg_no, $set_includes_uninitialized, $uninitialized_arg_no);

    @sets = split (/,\s*/, $set_list);
    @return_sets = @sets;
    $arg_no = 0;
    $set_includes_uninitialized = 0;
    $uninitialized_arg_no = -1;
    while ($set_name = shift (@sets)) {
	if ($set_name !~ /^[\w-]+$/) {
	    return ($arg_no, $SET_NAME_INVALID, @return_sets);
	}
	elsif (!$self->defined_set ($set_name)) {
	    return ($arg_no, $SET_UNDEFINED, @return_sets);
	}
	elsif (grep (/^$set_name$/, @sets)) {
	    return ($arg_no, $SET_REDUNDANT, @return_sets);
	}
	elsif ($set_name eq 'new' || $set_name eq 'uninitialized') {
	    $return_sets[$arg_no] = 'new';
	    $set_includes_uninitialized = 1;
	    $uninitialized_arg_no = $arg_no;
	}
	else {
	    $return_sets[$arg_no] = $self->long_name($set_name);
	}
	$arg_no++;
    }
    return ($uninitialized_arg_no, $set_includes_uninitialized, @return_sets);
}

# Internal subroutine to give the tree-relative form of an absolute
# exception path, for the config error message, or undef if the path
# is not in the tree.
sub _relative_hint {
    my ($tree, $path) = @_;

    $path =~ s{/+\z}{} if ($path ne '/');
    return '.' if ($path eq $tree);
    return $1 if ($path =~ m{^\Q$tree\E/+(.+)\z});
    return undef;
}

# Internal subroutine to convert a set array to a set list.
sub _set_array_to_set_list {
    my (@sets) = @_;
    my ($set_list);

    $set_list = join (',', @sets);
    return ($set_list);
}

# Method to return array of all sets.
sub all_sets {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($set, $set_long_name, $set_short_name, @all_sets);

    foreach $set (@{$self->{SETS}}) {
	($set_long_name, $set_short_name) = split (/,/, $set);
	push (@all_sets, $set_long_name);
    }

    return (@all_sets);
}

# Method to return array of all trees.
sub all_trees {
    my $self = shift;
    my $class = ref ($self) || $self;

    return (@{$self->{TREES}});
}

# Method to return set info (keywords and priority) for a
# given set.
sub set_info {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($set) = @_;
    my ($description, $keywords, $priority);

    $set = $self->long_name ($set);
    $description = ${$self->{DESCRIPTION}}{$set};
    $keywords = ${$self->{KEYWORDS}}{$set};
    $priority = ${$self->{PRIORITY}}{$set};

    return ($description, $keywords, $priority);
}

# Method to return 1 if there's any intersection between two set
# lists--the set list associated with a path and the sets specified
# by the user in arguments to sigtree.  It assumes both set lists
# are valid.
sub _set_lists_intersect {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($path_set_list, @sets) = @_;
    my (@path_sets, $set1, $set2);

    @path_sets = split (/,\s*/, $path_set_list);
    foreach $set1 (@path_sets) {
	foreach $set2 (@sets) {
	    return 1 if ($self->long_name($set1) eq $self->long_name($set2));
	}
    }
    return 0;
}

# Method to add 'new' set to all uninitialized trees.
sub add_new_set_to_uninitialized_trees {
    my ($self) = shift;
    my ($class) = ref ($self) || $self;
    my ($spec_dir) = @_;
    my (@trees, $tree, $tree_spec_name);
    
    @trees = $config->all_trees;
    foreach $tree (@trees) {
	$tree_spec_name = path_to_spec ($tree);
	if (!-e "$spec_dir/$tree_spec_name") {
	    _add_set_to_tree ($tree, 'new');
	}
    }
}

# Method to add a set to a tree (currently used only to add 'new'
# to trees that don't have an initialized spec, for use with
# -s new|uninitialized initialize.
sub _add_set_to_tree {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree, $set) = @_;

    ${$self->{TREE_SETS}}{$tree} .= ',' . $set;
}

# Method to return 1 if any sets in a list are referenced within a
# given tree.
sub tree_uses_sets {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree, @sets) = @_;
    my ($tree_sets);

    $tree_sets = ${$self->{TREE_SETS}}{$tree};

    return ($self->_set_lists_intersect ($tree_sets, @sets));
}

# Method to return 1 if any trees are members of the given set.
sub set_has_trees {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($set) = @_;
    my $tree;

    foreach $tree (@{$self->{TREES}}) {
	if ($self->tree_uses_sets ($tree, $set)) {
	    return 1;
	}
    }

    return 0;
}

# Method to return the set list for a given path.
# It assumes that the tree and path are valid.
# It does not necessarily return primary (long) names.
sub path_set_list {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree, $path) = @_;
    my (@path_components, $test_path, $set_list);

    # First, if we're looking at the tree itself, check for a "." exception.
    if ($path eq '.') {
	if (defined (${$self->{TREE_EXCEPTION_SETS}}{$tree}{"."})) {
            $set_list = ${$self->{TREE_EXCEPTION_SETS}}{$tree}{"."};
            return ($set_list);
        }
    }

    # Next, look at exact-match exceptions.
    if (defined (${$self->{TREE_EXCEPTION_SETS}}{$tree}{$path})) {
        $set_list = ${$self->{TREE_EXCEPTION_SETS}}{$tree}{$path};
        return ($set_list);
    }

    # For tree exceptions (exception-tree directories under a tree), walk
    # through possible exceptions, most specific to least specific, to see
    # if one is defined.  If so, set list comes from that.  If not, we get
    # it from the tree's set list.
    @path_components = split (/\//, $path);
    while ($#path_components >= 0) {
	$test_path = join ('/', @path_components);
	if (defined (${$self->{TREE_DIR_EXCEPTION_SETS}}{$tree}{$test_path})) {
	    $set_list = ${$self->{TREE_DIR_EXCEPTION_SETS}}{$tree}{$test_path};
            return ($set_list);
        }
        pop (@path_components);
    }

    $set_list = ${$self->{TREE_SETS}}{$tree};
    return ($set_list);
}

# Method to return 1 if a tree/path is a member of a set list.
# It assumes that the tree, path, and set list are valid.
sub path_in_sets {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree, $path, @sets) = @_;
    my ($path_set_list);

    $path_set_list = $self->path_set_list ($tree, $path);
    return ($self->_set_lists_intersect ($path_set_list, @sets));
}

# Method to return 1 if a tree/path is to be ignored.
sub path_is_ignored {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree, $path) = @_;
    my ($primary_set, $description, $keywords, $priority);
    my ($keyword, @keywords_array);

    $primary_set = $self->primary_set_for_path ($tree, $path);
    ($description, $keywords, $priority) = $self->set_info ($primary_set);

    @keywords_array = split (/,\s*/, $keywords);
    foreach $keyword (@keywords_array) {
	return 1 if ($keyword eq 'ignore');
    }
    return 0;
}

# Method to return SHA digest attribute for path.
sub path_sha_digest {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree, $path) = @_;
    my ($primary_set, $description, $keywords, $priority);
    my ($keyword, @keywords_array);
    my ($sha_digest);

    $sha_digest = 0;

    $primary_set = $self->primary_set_for_path ($tree, $path);
    ($description, $keywords, $priority) = $self->set_info ($primary_set);

    @keywords_array = split (/,\s*/, $keywords);
    foreach $keyword (@keywords_array) {
	$sha_digest = $self->{SHA_DIGEST} . '-' . $self->{SHA_DIGEST_BITS} if ($keyword eq 'sha2digest' || $keyword eq 'sha3digest' || $keyword eq 'shadigest');
    }

    return $sha_digest;
}

# Method to return 1 if the primary set for a path checks a keyword.
sub path_uses_keyword {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree, $path, $keyword) = @_;

    my $primary_set = $self->primary_set_for_path ($tree, $path);
    my ($description, $keywords, $priority) = $self->set_info ($primary_set);
    return (grep { $_ eq $keyword } split (/,\s*/, $keywords // '')) ? 1 : 0;
}

# Method to return the primary set name for a given path.
sub primary_set_for_path {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree, $path) = @_;
    my ($path_set_list, @sets);

    # If it's in the root dir, it's in the sigtree set.
    # This is special-cased because the root dir and spec dirs can't be
    # trees returned by $config->all_trees, or we'll cause some infinite
    # recursion issues.
    # So is the spec dir, which an absolute -d can put outside the root
    # dir (without this, path_set_list found no set for it).
    foreach my $dir ($root_dir, $spec_dir) {
	return ('sigtree') if (defined ($dir) && $tree =~ m{^\Q$dir\E(?:/|\z)});
    }

    $path_set_list = $self->path_set_list ($tree, $path);
    @sets = split (/,\s*/, $path_set_list);
    return ($sets[0]);
}

# Method to return the name of a tree a path is found in (or 0 if
# it's not in any of them).
sub tree_for_path {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($path) = @_;
    my ($tree);

    foreach $tree (@{$self->{TREES}}) {
	if ($path eq $tree || $path =~ /^\Q$tree\E\//) {
	    return ($tree);
	}
    }

    return 0;
}

1;

### End Config package.

### PrivSep package.
# Subroutines for privilege separation, so most of sigtree.pl can run
# under nonprivileged user and group _sigtree, with required privileged
# operations run as root.
# Some of these subroutines, as noted, are directly duplicated from
# reportnew.
#
###############################################################################
# IPC PROTOCOL (LENGTH-PREFIXED MESSAGES)
# These are generic functions used by both main process and FileAttr
###############################################################################
package PrivSep;

use strict;
use warnings;
use Errno qw( ENOENT ENOTDIR ); # in request_stat
use MIME::Base64;

# Try to load JSON (with fallback)
my $json_loaded = 0;
BEGIN {
    if (eval { require JSON::MaybeXS; JSON::MaybeXS->import(qw(encode_json decode_json)); 1 }) {
        $json_loaded = 1;
    }
    elsif (eval { require JSON::PP; JSON::PP->import(qw(encode_json decode_json)); 1 }) {
        $json_loaded = 1;
    }
    else {
        die "No JSON module available (need JSON::MaybeXS or JSON::PP)\n";
    }
}

# Subroutine to send request from nonprivileged to privileged side.
sub send_request {
    my ($sock, $request) = @_;

    # Add unique ID for debugging
    state $req_id = 0;
    $request->{_req_id} = ++$req_id;

    print "DEBUG: [CHILD] [PID $$] Sending request #$req_id  type=$request->{type} $request->{path}\n" if ($main::debug_flag);

    # Base64-encode paths to handle non-UTF8 filenames
    # JSON requires valid UTF-8 strings, but Unix filenames can contain
    # arbitrary bytes (like \x88). Base64 encoding preserves all bytes.
    if (exists $request->{path}) {
	$request->{path_b64} = encode_base64 ($request->{path}, ''); # '' no newlines
	delete $request->{path};
    }
    my $json = encode_json($request);
    my $len = pack('N', length($json));

    if ($main::debug_flag) {
        warn "DEBUG: [CHILD] send_request [PID $$]: json_len=" . length($json) . 
	    " packed_len_hex=" . unpack('H*', $len) . "\n";
    }

    my $data = $len . $json;
    my $total = length ($data);
    my $written = 0;

    if ($main::debug_flag) {
        warn "DEBUG: [CHILD] send_request [PID $$]: total_bytes=$total (4 + " . length($json) . ")\n";
    }

    # A write to a socket whose reader has gone raises SIGPIPE, which
    # would kill this process silently; make it a write error instead.
    local $SIG{PIPE} = 'IGNORE';
    while ($written < $total) {
	my $n = syswrite ($sock, $data, $total - $written, $written);
	if (!defined $n) {
	    # Without the privileged parent nothing more can be done.
	    die "send_request: lost connection to privileged parent: $!\n";
	}
	$written += $n;
    }

    if ($main::debug_flag) {
        warn "DEBUG: [CHILD] send_request: actually wrote $written bytes\n";
    }
}

# Subroutine to receive a request on the privileged side.
sub recv_request {
    my ($sock) = @_;
    # Max request size: 1MB for large file paths and Base64-encoded data
    my $MAX_REQUEST_LENGTH = 1024 * 1024;
    # Previously was 10MB (10_000_000)
    
    # Read 4-byte length
    my $len_packed;
    my $bytes_read = sysread($sock, $len_packed, 4);
    
    return undef unless $bytes_read == 4;
    
    my $len = unpack('N', $len_packed);
    
    # Sanity check
    return undef if $len > $MAX_REQUEST_LENGTH;  # 1 MB max
    
    # Read data
    my $json = '';
    while (length($json) < $len) {
        my $chunk = '';
        my $remaining = $len - length($json);
        my $n = sysread($sock, $chunk, $remaining);
        
        return undef unless $n > 0;
        $json .= $chunk;
    }
    
    my $request = eval { decode_json($json) };
    if ($@) {
        warn "JSON decode error in recv_request: $@\n";
        return undef;
    }

    # Base64-decode path
    if (exists $request->{path_b64}) {
	$request->{path} = decode_base64 ($request->{path_b64});
	delete $request->{path_b64};
    }
    
    return $request;
}

# Subroutine to send a response from the privileged side.
sub send_response {
    my ($sock, $response) = @_;

    my $json = encode_json($response);
    my $len = pack('N', length($json));

    my $data = $len . $json;
    my $total = length ($data);
    my $written = 0;

    # A worker that has died must not take the privileged parent (and so
    # every other worker) with it: make SIGPIPE a write error. Local, so
    # the commands this process execs keep the default disposition.
    local $SIG{PIPE} = 'IGNORE';
    while ($written < $total) {
	my $n = syswrite ($sock, $data, $total - $written, $written);
	if (!defined $n) {
	    warn "send_response: syswrite failed: $!\n";
	    return;
	}
	$written += $n;
    }
}

# Subroutine to receive a response on the nonprivileged side. Dies if no
# valid response arrives: after a short read, a bad length or bad JSON the
# stream is out of step, so no later request on it could be trusted, and
# the callers would otherwise read the undefined response as success.
sub recv_response {
    my ($sock) = @_;
    my $response = _recv_response_raw ($sock);
    defined ($response) or
	die "Lost or corrupted connection to privileged parent [PID $$]\n";
    return $response;
}

# Read one response; returns undef (after a warning) on any failure.
sub _recv_response_raw {
    my ($sock) = @_;
    # Max request size: 1MB for large file paths and Base64-encoded data
    my $MAX_REQUEST_LENGTH = 1024 * 1024;

    if ($main::debug_flag) {
        warn "DEBUG: recv_response [PID $$] ENTERED, socket fd=" . fileno($sock) . "\n";
    }

    # Read 4-byte length
    my $len_packed;
    my $bytes_read = sysread($sock, $len_packed, 4);
    
    if ($bytes_read != 4) {
        warn "recv_response [PID $$]: Failed to read length prefix (got $bytes_read bytes)\n";
        return undef;
    }
    
    my $len = unpack('N', $len_packed);

    # Sanity check: JSON responses should be at least 2 bytes (e.g., "{}")
    # and reasonably sized (under 1MB)
    if ($len < 2) {
	warn "recv_response [PID $$]: Suspiciously small length ($len)\n";
	warn "  Length bytes (hex): " . unpack('H*', $len_packed) . "\n";
	return undef;
    }

    if ($len > $MAX_REQUEST_LENGTH) {
	warn "recv_response [PID $$]: Response too large ($len bytes)\n";
	return undef;
    }
    
    # Read data
    my $json = '';
    while (length($json) < $len) {
        my $chunk = '';
        my $remaining = $len - length($json);
        my $n = sysread($sock, $chunk, $remaining);

	if (!defined $n || $n <= 0) {
            warn "recv_response [PID $$]: Read failed or EOF (read returned " . (defined $n ? $n : 'undef') . ")\n";
            warn "  Expected $len bytes, got " . length($json) . " so far\n";
            return undef;
        }

        $json .= $chunk;
    }

    # VERIFY: We read exactly $len bytes, no more
    if (length($json) != $len) {
	warn "FATAL [PID $$]: recv_response read " . length($json) . " bytes but expected $len!\n";
	die "Socket corruption detected\n";
    }

    # Debug: show what we're trying to decode
    if ($main::debug_flag) {
        my $preview = substr($json, 0, 100);
        warn "DEBUG: recv_response [PID $$]: Received $len bytes, first 100 chars: $preview\n";
    }
    
    my $response = eval { decode_json($json) };
    if ($@) {
        warn "JSON decode error in recv_response [PID $$]: $@\n";
        
        # Show what we actually received
        my $hex_preview = unpack('H*', substr($json, 0, 32));
        my $char_preview = substr($json, 0, 32);
        $char_preview =~ s/([^[:print:]])/sprintf("\\x%02x", ord($1))/ge;
        
        warn "  Length field said: $len bytes\n";
        warn "  Actually received: " . length($json) . " bytes\n";
        warn "  First 32 bytes (hex): $hex_preview\n";
        warn "  First 32 bytes (escaped): $char_preview\n";
        
        return undef;
    }

    if ($main::debug_flag && $response->{_req_id}) {
	warn "DEBUG: [PID $$] Received response for request #$response->{_req_id}\n";
    }
    
    return $response;
}

###############################################################################
# HIGH-LEVEL REQUEST FUNCTIONS
# These can be called from anywhere with appropriate socket
###############################################################################

# Request a privileged stat operation
# Args: $sock (socket), $path (file path)
# Returns: Array of stat values (dev, ino, mode, ...) or empty list on error
sub request_stat {
    my ($sock, $path) = @_;
    
    my $request = {
        type => 'STAT',
        path => $path,
    };
    
    send_request($sock, $request);
    my $response = recv_response($sock);
    
    if ($response->{error}) {
	# Do not warn for a path that is simply not there: ENOENT, or
	# ENOTDIR when a directory in the spec has become a file (an app
	# update turning a .nib bundle into a flat .nib, say), so its
	# recorded children are reported as deleted without a warning each.
	my $errno = $response->{errno} // 0;
	unless ($errno == ENOENT || $errno == ENOTDIR ||
		(!$errno && $response->{error} =~ /No such file or directory/)) {
	    warn "Privileged stat failed: " . AttrDisplay::esc ($response->{error}) . "\n";
	}
        return ();
    }
    
    return (
        $response->{dev},
        $response->{ino},
        $response->{mode},
        $response->{nlink},
        $response->{uid},
        $response->{gid},
        $response->{rdev},
        $response->{size},
        $response->{atime},
        $response->{mtime},
        $response->{ctime},
        $response->{blksize},
        $response->{blocks},
    );
}

# Request a privileged file open.
sub request_open {
    my ($sock, $path, $mode, $expect_dev, $expect_ino) = @_;
    $mode //= '<'; # Default to read
    
    my $request = {
        type => 'OPEN',
        path => $path,
	mode => $mode,
    };

    $request->{expect_dev} = $expect_dev if defined $expect_dev;
    $request->{expect_ino} = $expect_ino if defined $expect_ino;
    
    send_request($sock, $request);
    my $response = recv_response($sock);
    
    if ($response->{error}) {
	if ($mode eq '>') {
	    warn "Cannot write to " . AttrDisplay::esc ($path) . ": " . AttrDisplay::esc ($response->{error}) . "\n";
	}
	else {
	    warn "Privileged open failed: " . AttrDisplay::esc ($response->{error}) . "\n";
	}
	return undef;
    }

    if ($response->{success}) {
	# Now receive file descriptor from privileged parent. The parent
	# sends it right after the response; bound the wait so that a
	# parent that never sends it cannot hang this process forever
	# (this was the only job of the old Linux ACK's timeout). After a
	# timeout the stream is out of step, so the process dies.
	my $fd;
	eval {
	    local $SIG{ALRM} = sub { die "timeout\n"; };
	    alarm (30);
	    $fd = IO::FDPass::recv (fileno ($sock));
	    alarm (0);
	};
	alarm (0);
	if ($@) {
	    die "Timed out waiting for file descriptor for $path from privileged parent [PID $$]\n";
	}

	warn "DEBUG: [PID $$] After recv FD, got fd=$fd for $path\n" if ($main::debug_flag);

	if (!defined $fd || $fd < 0) {
	    warn "Failed to receive file descriptor for " . AttrDisplay::esc ($path) . " [PID $$]\n";
	    return undef;
	}

	# OpenBSD: Verify socket is still readable
	if ($^O eq 'openbsd' && $main::debug_flag) {
	    my $select = IO::Select->new($sock);
	    my $readable = $select->can_read(0) ? "YES" : "NO";
	    warn "DEBUG: [PID $$] After FD recv, socket readable: $readable\n";
	}

	# Convert file descriptor to Perl filehandle
	# Use appropriate mode for fdopen
	my $fdopen_mode = $mode eq '>' ? '>&=' : '<&=';
	open(my $fh, $fdopen_mode, $fd) or do {
	    warn "Failed to fdopen received descriptor: $!\n";
	    require POSIX;
	    POSIX::close($fd); # Clean up orphaned fd.
	    return undef;
	};
    
	return $fh;
    }

    # Neither success nor error.
    die "Protocol error: OPEN response has neither success nor error. [PID $$]\n";
}

sub request_readdir {
    my ($sock, $path) = @_;
    
    my $request = {
        type => 'READDIR',
        path => $path,
    };
    
    send_request($sock, $request);
    my $response = recv_response($sock);
    
    if ($response->{error}) {
        warn "Privileged readdir failed: " . AttrDisplay::esc ($response->{error}) . "\n";
        return [];
    }

    # Base64 decode each entry.
    my @decoded = map { decode_base64 ($_) } @{$response->{entries} || []};
    return \@decoded;
}

sub request_readlink {
    my ($sock, $path) = @_;
    
    my $request = {
        type => 'READLINK',
        path => $path,
    };
    
    send_request($sock, $request);
    my $response = recv_response($sock);
    
    if ($response->{error}) {
        warn "Privileged readlink failed: " . AttrDisplay::esc ($response->{error}) . "\n";
        return undef;
    }

    # Base64 decode target
    return (decode_base64 ($response->{target_b64}), $response->{target_type});;
}

sub request_immutable_get {
    my ($sock, $path) = @_;
    
    my $request = {
        type => 'IMMUTABLE_GET',
        path => $path,
    };
    
    send_request($sock, $request);
    my $response = recv_response($sock);
    
    if ($response->{error}) {
        warn "Privileged immutable check failed: " . AttrDisplay::esc ($response->{error}) . "\n";
        return undef;
    }
    
    return $response->{flags};
}

sub request_immutable_set {
    my ($sock, $path, $immutable) = @_;
    
    my $request = {
        type => 'IMMUTABLE_SET',
        path => $path,
        immutable => $immutable,
    };
    
    send_request($sock, $request);
    my $response = recv_response($sock);
    
    if ($response->{error}) {
        # The error names the path and whether it was a set or reset.
        my $error = $response->{error};
        chomp ($error);
        die "Immutable flag request refused or failed: $error\n";
    }
    
    return 1;
}

sub request_delete_file {
    my ($sock, $path) = @_;
    
    my $request = {
        type => 'DELETE_FILE',
        path => $path,
    };
    
    send_request($sock, $request);
    my $response = recv_response($sock);
    
    if ($response->{error}) {
        warn "Failed to delete file $path: $response->{error}\n";
        return 0;
    }
    
    return 1;
}

sub request_sign_file {
    my ($sock, $file, $pgp_passphrase) = @_;

    # The privileged parent signs with its own method and key; the
    # request carries only the file and the passphrase.
    my $request = {
        type => 'SIGN_FILE',
        path => $file,
        passphrase => $pgp_passphrase,
    };
    
    send_request($sock, $request);
    my $response = recv_response($sock);
    
    if ($response->{error}) {
        die "Failed to sign file $file: $response->{error}\n";
    }
    
    return 1;
}

# Dies if the privileged parent could not sign a test file with this
# passphrase.
sub request_check_passphrase {
    my ($sock, $pgp_passphrase) = @_;

    send_request ($sock, { type => 'CHECK_PASSPHRASE',
			   passphrase => $pgp_passphrase });
    my $response = recv_response ($sock);

    die $response->{error} if ($response->{error});
    return 1;
}

sub request_verify_signature {
    my ($sock, $file) = @_;

    my $request = {
        type => 'VERIFY_SIGNATURE',
        path => $file,
    };
    
    send_request($sock, $request);
    my $response = recv_response($sock);
    
    if ($response->{error}) {
        warn "Failed to verify signature for $file: $response->{error}\n";
        return 0;
    }
    
    return $response->{verified};
}

1;
### End PrivSep package.

### FileAttr package.

# Methods to get information about an individual file, compare
# a file's attributes against an existing spec, etc.
package FileAttr;

use strict;
use warnings;
use Cwd qw( abs_path ); # used in _canonicalize_link_target
use Errno qw( EACCES EPERM ELOOP EMLINK ); # ELOOP EMLINK in _get_sha_digest
use Fcntl qw( :DEFAULT O_NOFOLLOW :mode ); # For S_IRUSR, S_IRGRP, S_IROTH, etc.; :DEFAULT and O_NOFOLLOW for sysopen in _get_sha_digest
use File::Basename;
use File::Spec;

our $PRIV_IPC;
our %DIR_ACCESS_CACHE;

# Flags read in batches by prefetch_flags, keyed by full path, each used
# (and removed) by the next _get_file_flags for that path. One flags
# command per path forks this whole process, and a process holding a
# large spec makes each fork slow (most of the time of a macOS check or
# update).
our %FLAGS_CACHE;
# Paths per ls/lsattr run. A constant, not "my $x = 200": this package's
# file-scoped assignments run only when execution reaches them, after
# the main program above has already called in here.
use constant FLAGS_BATCH => 200;

## Subroutines for privilege separation. Written by Claude.

# Check if mode bits allow world read
sub is_world_readable {
    my ($mode) = @_;
    return ($mode & S_IROTH) ? 1 : 0;
}

# Check if mode bits allow world execute (for directories)
sub is_world_executable {
    my ($mode) = @_;
    return ($mode & S_IXOTH) ? 1 : 0;
}

# Check if we can access parent directory unprivileged
# Returns: (can_access, parent_mode)
sub can_access_parent_unprivileged {
    my ($path) = @_;
    
    my $dir = dirname($path);
    
    # Check cache first. Cache is not updated; permissions could change
    # during run.
    if (exists $DIR_ACCESS_CACHE{$dir}) {
        return ($DIR_ACCESS_CACHE{$dir}, undef);
    }
    
    # Try to stat parent directory unprivileged
    my @parent_stat = lstat($dir);
    
    if (!@parent_stat) {
        # Can't stat parent unprivileged - need privileges
        $DIR_ACCESS_CACHE{$dir} = 0;
        return (0, undef);
    }
    
    my $parent_mode = $parent_stat[2];
    
    # Check if parent is world-accessible (read + execute for directories)
    if (!is_world_readable($parent_mode) || !is_world_executable($parent_mode)) {
        $DIR_ACCESS_CACHE{$dir} = 0;
        return (0, $parent_mode);
    }
    
    $DIR_ACCESS_CACHE{$dir} = 1;
    return (1, $parent_mode);
}

# Check if we (as unprivileged user) can read this path
# For files: need world read AND parent directory accessible
# For directories: need world read AND execute AND parent accessible
sub can_access_unprivileged {
    my ($path, $mode, $is_dir) = @_;

    # Check the immediate path permissions
    if ($is_dir) {
        return 0 unless is_world_readable($mode) && is_world_executable($mode);
    } else {
        return 0 unless is_world_readable($mode);
    }
    
    # Also need to check parent directory permissions
    my ($parent_accessible, $parent_mode) = can_access_parent_unprivileged($path);
    return $parent_accessible;
}

## END Subroutines for privilege separation.

# Method to create a new FileAttr record.
# $special means it doesn't exist (either an old file deleted
# or a new file created).
sub new {
    my $class = shift;
    my ($tree, $path, $sha_digest, $special) = @_;
    my ($sha_version, $sha_bits);
    my ($full_path, $base_dir, $link_target, $self, $ctx, $digest,
	$flags);
    my ($parent_accessible, $parent_mode, @stat, $stat_failed);

    $self->{TREE} = $tree;
    if ($path eq '.') {
	$self->{PATH} = $tree;
	$full_path = $tree;
    }
    else {
	$self->{PATH} = $path;
	$full_path = $tree . '/' . $path;
    }

    if ($special) {
	$self->{TYPE} = 'nonexistent';
	bless $self, $class;
	return $self;
    }

    ($parent_accessible, $parent_mode) = can_access_parent_unprivileged ($full_path);

    $stat_failed = 0;

    # stat directly if not using privilege separation.
    if (!$main::use_privsep) {
	@stat = lstat ($full_path);
	$stat_failed = 1 unless @stat;
    }
    elsif ($parent_accessible) {
	# Parent is accessible, try to stat unprivileged.
	@stat = lstat ($full_path);

	if (!@stat && ($! == EACCES || $! == EPERM)) {
	    # Unexpected - parent is accessible but we can't stat.
	    # Fall back to privileged.
	    @stat = PrivSep::request_stat ($PRIV_IPC, $full_path);
	    $stat_failed = 1 unless @stat;
	}
	elsif (!@stat) {
	    # Other error (likely ENDENT - file doesn't exist)
	    $stat_failed = 1;
	}
    }
    else {
	# Parent not accessible, must use privileged stat.
	@stat = PrivSep::request_stat ($PRIV_IPC, $full_path);
	$stat_failed = 1 unless @stat;
    }

    if ($stat_failed) {
	# File doesn't exist - mark as nonexistent.
	$self->{TYPE} = 'nonexistent';
	bless $self, $class;
	return $self;
    }

    # Populate $self with stat info.
#    $self->{DEV} = $stat[0]; # unused
#    $self->{INO} = $stat[1]; # unused
    $self->{MODE} = $stat[2];
    $self->{NLINK} = $stat[3];
    $self->{UID} = $stat[4];
    $self->{GID} = $stat[5];
    # Device number, for device nodes only (the rdev keyword compares it).
    # Its encoding of major and minor differs by OS; see device_number.
    $self->{RDEV} = $stat[6] if (S_ISCHR ($stat[2]) || S_ISBLK ($stat[2]));
    $self->{SIZE} = $stat[7];
#    $self->{ATIME} = $stat[8]; # unused
    $self->{MTIME} = $stat[9];
    $self->{CTIME} = $stat[10];
#    $self->{BLKSIZE} = $stat[11]; # unused
#    $self->{BLOCKS} = $stat[12]; # unused

    my $mode = $stat[2];

    # Now we know the mode bits - use them to decide if we need privileges for reading
    # file content (even if we could stat it).
    # If privsep is disabled, we never "need" privileges.
    my $need_priv = $main::use_privsep && !can_access_unprivileged ($full_path, $mode, S_ISDIR ($mode));

    # Determine file type and get type-specific data.
    $self->{TYPE} = _get_file_type ($mode);
    
    if ($self->{TYPE} eq 'file') {
	# Get SHA digest if requested.
	if ($sha_digest) {
	    # add dev and ino at end
	    $self->{SHADIGEST} = _get_sha_digest ($full_path, $sha_digest, $need_priv, $stat[0], $stat[1]);
	}
    }
    elsif ($self->{TYPE} eq 'dir') {
	# Get directory contents.
	$self->{FILES} = _get_dir_contents ($full_path, $need_priv);
    }
    elsif ($self->{TYPE} eq 'link') {
	# Claude has lost $self->{LINKTARGET_TYPE} which could require privs.
	# (and could be another link)
	my ($link_target, $linktarget_type) = _get_link_target ($full_path, $need_priv);

	# Canonicalize target to absolute path. Done in privileged parent
	# if privsep is enabled, or locally if disabled.
	if (!$main::use_privsep && defined ($link_target)) {
	    # Without privsep we have full access and canonicalize here.
	    $link_target = _canonicalize_link_target ($full_path, $link_target);
	    $linktarget_type = _get_local_linktarget_type ($link_target);
	}
	# With privsep, the privileged parent already canonicalized it and
	# returned the link target type.
	$self->{LINK} = $link_target;
	$self->{LINKTARGET_TYPE} = $linktarget_type;
    }

    # Get immutable flags if supported (may need privilege), but only if
    # this path's set checks them: reading them costs a fork per path
    # unless prefetch_flags has already read them.
    if ($config->path_uses_keyword ($tree, $path, 'flags')) {
	$self->{FLAGS} = _get_file_flags ($full_path, $need_priv);
    }

    bless $self, $class;
    return $self;
}

# A device number as "major,minor", decoded as this OS encodes it (as
# OpenBSD's, macOS's and glibc's major() and minor() macros do), or the
# raw number on another OS. A spec from another OS shows its own
# encoding decoded wrongly, so verify_hosts shows raw numbers.
sub device_number {
    my ($rdev) = @_;
    return '(none)' unless (defined ($rdev) && $rdev =~ /^\d+\z/);
    my ($major, $minor);
    if ($^O eq 'openbsd') {
	$major = ($rdev >> 8) & 0xff;
	$minor = ($rdev & 0xff) | (($rdev & 0xffff0000) >> 8);
    }
    elsif ($^O eq 'darwin') {
	$major = ($rdev >> 24) & 0xff;
	$minor = $rdev & 0xffffff;
    }
    elsif ($^O eq 'linux') {
	$major = (($rdev >> 8) & 0xfff) | (($rdev >> 32) & 0xfffff000);
	$minor = ($rdev & 0xff) | (($rdev >> 12) & 0xffffff00);
    }
    else {
	return $rdev;
    }
    return "$major,$minor";
}

# Internal method to get file type.
sub _get_file_type {
    my ($mode) = @_;

    return 'nonexistent' if (!defined ($mode));

    return 'file' if (S_ISREG ($mode));

    return 'dir' if (S_ISDIR ($mode));

    return 'link' if (S_ISLNK ($mode));

    return 'block device' if (S_ISBLK ($mode));

    return 'char device' if (S_ISCHR ($mode));

    return 'fifo' if (S_ISFIFO ($mode));

    return 'socket' if (S_ISSOCK ($mode));

    return '<undefined>';
}

# Internal method to canonicalize link targets.
sub _canonicalize_link_target {
    my ($full_path, $link_target) = @_;
    my ($base_dir);

    # Need absolute path to be able to obtain other information about the target.
    if (substr ($link_target, 0, 1) ne '/') {
	# Basedir could be a directory within $tree, not $tree itself.
	$base_dir = File::Basename::dirname ($full_path);
	$link_target = File::Spec->catfile ($base_dir, $link_target);
    }

    if ($link_target =~ /\.\./) {
	# Get actual target; if nonexistent, get best estimate
	my $abs_link_target = abs_path ($link_target);

	if (!defined ($abs_link_target)) {
	    # Avoid use of cwd in File::Spec->rel2abs
	    $base_dir = File::Basename::dirname ($full_path) if (!defined ($base_dir));
	    $abs_link_target = File::Spec->rel2abs ($link_target, $base_dir);
	}
	$link_target = $abs_link_target;
    }

    return $link_target;
}

# Internal method to get SHA digest. Claude rewrote this and lost the SHA3 support, so
# I rewrote it again.
sub _get_sha_digest {
    my ($full_path, $sha_digest, $need_priv, $dev, $ino) = @_;
    my ($fh, $sha_version, $sha_bits, $digest);
    my $opened_locally = 0;

    # Determine which SHA digest to use.
    if ($sha_digest =~ /-/) {
	($sha_version, $sha_bits) = split (/-/, $sha_digest);
    }
    else {
	return '<undefined>';
    }
    
    # If privsep is disabled, always open directly
    if (!$main::use_privsep) {
        if (!sysopen ($fh, $full_path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)) {
	    my $err = $!;
	    if ($err == ELOOP || $err == EMLINK) {
		warn "File type changed between stat and open "
		    . "(now a symlink): " . AttrDisplay::esc ($full_path) . " ($err)\n";
	    }
            return undef;
        }
	$opened_locally = 1;
    }
    elsif ($need_priv) {
        # Request file descriptor from privileged parent
        $fh = PrivSep::request_open ($FileAttr::PRIV_IPC, $full_path, '<', $dev, $ino);
        return undef unless $fh;
    }
    else {
        # Try to open unprivileged
        if (!sysopen ($fh, $full_path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)) {
	    my $err = $!;
	    if ($err == ELOOP || $err == EMLINK) {
		warn "File type changed between stat and open "
		    . "(now a symlink): " . AttrDisplay::esc ($full_path) . " ($err)\n";
		return undef;
	    }
            # Unexpected - mode said we could read but we can't
            # Fall back to privileged
            $fh = PrivSep::request_open($FileAttr::PRIV_IPC, $full_path, '<', $dev, $ino);
            return undef unless $fh;
        }
	else {
	    $opened_locally = 1;
	}
    }

    if ($opened_locally) {
	# If the caller told us which inode it stat'd, confirm we opened the
	# same object. Catches what O_NOFOLLOW can't: an intermediate directory
	# component swapped for a symlink, or the file replaced by a different
	# inode (rename-over, hardlink swap, fifo/device).
	if (defined $dev && defined $ino) {
	    my @st = stat($fh);               # fstat on the open descriptor
	    unless (@st) {
		my $err = $!;
		close $fh;
		warn "fstat failed after open: $err (" . AttrDisplay::esc ($full_path) . ")\n";
		return undef;
	    }
	    if ($st[0] != $dev ||
		$st[1] != $ino) {
		close $fh;
		warn "File identity changed between stat and open "
		    . "(dev/ino mismatch): " . AttrDisplay::esc ($full_path) . "\n";
		return undef;
	    }
	}
    }
    
    # Now compute digest from the filehandle
    # This is the CPU-intensive work, done unprivileged
    if ($sha_version == 2) {
	$digest = Digest::SHA->new ($sha_bits);
    }
    elsif ($sha_version == 3) {
	$digest = Digest::SHA3->new ($sha_bits);
    }
    else {
	# Should not happen, screened out in config parsing.
	die "Internal error: ShA version unknown. $sha_version\n";
    }

    # addfile croaks ("Read failed: ...") if a read fails part way -- on
    # macOS, for instance, a cloud-backed file whose download times out
    # (ETIMEDOUT). That is a problem with one file, so report it and carry
    # on, as for a file that cannot be opened, rather than let it kill the
    # worker and with it the whole tree's results.
    unless (eval { $digest->addfile ($fh); 1 }) {
	my $err = $@;
	close $fh;
	$err =~ s/ at \S+ line \d+\.?\n?\z//;
	chomp ($err);
	warn AttrDisplay::esc ($err) . " (" . AttrDisplay::esc ($full_path) . ")\n";
	return undef;
    }
    close $fh;

    return $digest->hexdigest;
}

# Internal method to get directory contents. Written by Claude.
sub _get_dir_contents {
    my ($full_path, $need_priv) = @_;
    
    # If privsep disabled, always try directly
    if (!$main::use_privsep) {
        if (opendir (my $dh, $full_path)) {
            my @entries = grep { !/^\.\.?$/ } readdir($dh);
            closedir $dh;
            return \@entries;
        }
        return [];
    }
    
    if ($need_priv) {
        # Go straight to privileged
        return PrivSep::request_readdir ($FileAttr::PRIV_IPC, $full_path);
    }
    else {
        # Try unprivileged
        if (opendir (my $dh, $full_path)) {
            my @entries = grep { !/^\.\.?$/ } readdir($dh);
            closedir  $dh;
            return \@entries;
        } else {
            # Unexpected failure - fall back to privileged
            return PrivSep::request_readdir ($FileAttr::PRIV_IPC, $full_path);
        }
    }
}

# Internal method to get link target. Written by Claude.
# Modified to also return link target type.
sub _get_link_target {
    my ($full_path, $need_priv) = @_;
    my ($target, $mode, $type);
    
    # If privsep disabled, always try directly
    if (!$main::use_privsep) {
	$target = readlink ($full_path);
	return ($target, undef); # type will be determined by caller
    }
    
    if ($need_priv) {
        # Go straight to privileged
        # Privileged parent will canonicalize the target and return type.
	($target, $type) = PrivSep::request_readlink ($FileAttr::PRIV_IPC, $full_path);
        return ($target, $type);
    }
    else {
        # Try unprivileged
        $target = readlink($full_path);
        
        if (!defined $target && ($! == EACCES || $! == EPERM)) {
            # Fall back to privileged
            # Privileged parent will canonicalize the target
            ($target, $type) = PrivSep::request_readlink ($FileAttr::PRIV_IPC, $full_path);
	    return ($target, $type);
        }
	elsif (defined $target) {
            # We got it unprivileged, but need to canonicalize it ourselves
            # However, if canonicalization requires accessing restricted dirs,
            # we need to do it privileged. Try it, and if it fails, request
            # privileged readlink which will canonicalize with full access.
            my $canonical = _try_canonicalize_link_target ($full_path, $target);
            if (defined $canonical) {
		$type = _try_get_linktarget_type ($canonical);
		if (defined ($type)) {
		    # Got both canonical path and type
		    return ($canonical, $type);
		}
		else {
		    # Could canonicalize but not get type - need privileged access.
		    ($target, $type) = PrivSep::request_readlink ($FileAttr::PRIV_IPC, $full_path);
		    return ($target, $type);
		}
            }
	    else {
                # Canonicalization failed - need privileged access
                ($target, $type) = PrivSep::request_readlink ($FileAttr::PRIV_IPC, $full_path);
		return ($target, $type);
            }
        }

        return (undef, undef);
    }
}

# Internal method to get link target type without priv separation.
sub _get_local_linktarget_type {
    my ($target_path) = @_;

    # stat (not lstat) to follow the link target.
    my @stat = stat ($target_path);

    return 'nonexistent' unless @stat;

    my $mode = $stat[2];

    return _get_file_type ($mode);
}

# Internal method to get link target type.
sub _try_get_linktarget_type {
    my ($target_path) = @_;

    # Try to stat the link target.
    # If we hit permission errors, return under to indicate we need privileged
    # help.

    my @stat = stat ($target_path);

    if (!@stat) {
	# Could be nonexistent or permission denied.
	# If EACCES/EPERM, we need privileged help.
	if ($! == EACCES || $! == EPERM) {
	    return undef;
	}
	return 'nonexistent';
    }

    my $mode = $stat[2];

    return _get_file_type ($mode);
}

# Internal method to try link target canonicalization but return undef on permissions errors.
sub _try_canonicalize_link_target {
    my ($full_path, $link_target) = @_;
    
    # Try to canonicalize, but return undef if we hit permission errors
    # This indicates we need privileged help
    
    my ($base_dir, $abs_link_target);
    
    if (substr($link_target, 0, 1) ne '/') {
        $base_dir = File::Basename::dirname($full_path);
        $link_target = File::Spec->catfile($base_dir, $link_target);
    }
    
    if ($link_target =~ /\.\./) {
        use Cwd qw(abs_path);
        $abs_link_target = abs_path($link_target);
        
        if (!defined($abs_link_target)) {
            # Could be because target doesn't exist, or permission denied
            # Try rel2abs which doesn't require filesystem access
            $base_dir = File::Basename::dirname($full_path) if (!defined($base_dir));
            $abs_link_target = File::Spec->rel2abs($link_target, $base_dir);
            
            # This might have succeeded, or might be incomplete
            # We can't tell, so return it
        }
        $link_target = $abs_link_target;
    }
    
    return $link_target;
}

# Internal method to obtain file flags.  This is icky, I'd like to get them
# from lstat. Now supports privsep.
sub _get_file_flags {
    my ($full_path, $need_priv) = @_;
    my ($flags, $perms, $nlinks, $uid, $gid);

    # Read already by prefetch_flags? (It reads only what the unprivileged
    # process could read itself -- ls needs only stat, and lsattr is not
    # run on a path that needs privileges -- and gets the same flags root
    # would.)
    return delete $FLAGS_CACHE{$full_path} if (exists $FLAGS_CACHE{$full_path});

    if ($main::use_privsep && $need_priv) {
	return PrivSep::request_immutable_get ($FileAttr::PRIV_IPC, $full_path);
    }

    if (-e $CHFLAGS) {
	if (-e "$full_path") {
	    open (my $outfh, '-|', $LIST_FLAGS_CMD, $LIST_FLAGS_OPT, $full_path);
	    $flags = <$outfh>;
	    close ($outfh);
	    if (defined ($flags) && (length ($flags) > 0)) {
		chomp ($flags);
		($perms, $nlinks, $uid, $gid, $flags) = split (/\s+/, $flags);

		if (($flags eq '-') || ($flags !~ /^[\w,]+$/)) {
		    $flags = 'none';
		}
	    }
	    else {
		$flags = '<undefined>';
	    }
	}
	else {
	    $flags = '<undefined>';
	}
    }
    elsif (-e $CHATTR) { # Linux
	if ((!-l $full_path) &&
	    (!-c $full_path) &&
	    (!_on_nonstd_fs ($full_path))) {
	    open (my $outfh, '-|', $LSATTR, $LSATTR_FLAGS_OPT, $full_path);
	    $flags = <$outfh>;
	    close ($outfh);
	    chomp ($flags) if (defined ($flags));
	    ($flags) = split (/\s+/, $flags);
	}
	if (defined ($flags)) {
	    if ($flags =~ /^[-]+$/) {
		$flags = 'none';
	    }
	}
	else {
	    $flags = '<undefined>';
	}
    }

    return ($flags);
}

# Subroutine to read the flags of many paths of a tree with one ls (BSD,
# macOS) or lsattr (Linux) per $FLAGS_BATCH paths, into %FLAGS_CACHE,
# for paths whose set checks flags. @paths are relative to $tree ('.'
# for the tree itself). A path whose flags cannot be read this way is
# left out, and _get_file_flags then reads it on its own as before.
sub prefetch_flags {
    my ($tree, @paths) = @_;
    my @full_paths;

    return unless (-e $CHFLAGS || -e $CHATTR);
    foreach my $path (@paths) {
	next if ($config->path_is_ignored ($tree, $path));
	next unless ($config->path_uses_keyword ($tree, $path, 'flags'));
	push (@full_paths, ($path eq '.') ? $tree : "$tree/$path");
    }
    while (my @batch = splice (@full_paths, 0, FLAGS_BATCH)) {
	if (-e $CHFLAGS) {
	    _prefetch_bsd_flags (@batch);
	}
	else {
	    _prefetch_linux_flags (@batch);
	}
    }
}

# BSD/macOS: ls -lod/-lOd plus f, which keeps the operands in argument
# order. Each line is matched to its path: a line for a path ends with
# " path" (a symlink's has " path -> target"), so a line split by a
# newline in a name, or a path ls could not stat, just goes uncached.
# Matching in order, each line first against the next expected path,
# means a symlink whose target text looks like another path is still
# taken as its own line.
sub _prefetch_bsd_flags {
    my (@batch) = @_;

    # -e, as _get_file_flags tests: a dangling symlink has always been
    # recorded as <undefined>, so reading its flags now would report a
    # change for every one.
    my @existing = grep { -e $_ } @batch;
    return unless (@existing);
    open (my $outfh, '-|', $LIST_FLAGS_CMD, $LIST_FLAGS_OPT . 'f', @existing) or return;
    my @lines = <$outfh>;
    close ($outfh);
    my $i = 0;
    foreach my $line (@lines) {
	chomp ($line);
	for (my $j = $i; $j < @existing; $j++) {
	    my $path = $existing[$j];
	    my $names_path = ($line =~ /^l/) ?
		(index ($line, " $path -> ") >= 0) :
		(length ($line) > length ($path) &&
		 substr ($line, -(length ($path) + 1)) eq " $path");
	    next unless ($names_path);
	    my $flags = (split (/\s+/, $line))[4];
	    $flags = 'none' if (!defined ($flags) || $flags eq '-' || $flags !~ /^[\w,]+$/);
	    $FLAGS_CACHE{$path} = $flags;
	    $i = $j + 1;
	    last;
	}
    }
}

# Linux: lsattr -d, skipping what _get_file_flags skips (symlinks,
# character devices, filesystems without flags). lsattr prints
# "flags path", so each line names its path. lsattr has to open the
# file, so under privsep a path the unprivileged process cannot read is
# left to _get_file_flags, which asks the privileged parent, as before
# 1.28. (ls -lod needs only stat, so the BSD batch has no such limit.)
sub _prefetch_linux_flags {
    my (@batch) = @_;
    my (@candidates, %fs_type);

    @candidates = grep { !-l $_ && !-c $_ && -e $_ } @batch;
    if ($main::use_privsep) {
	@candidates = grep {
	    my $mode = (lstat ($_))[2];
	    defined ($mode) && can_access_unprivileged ($_, $mode, S_ISDIR ($mode));
	} @candidates;
    }
    return unless (@candidates);
    # One stat for the filesystem types, as _on_nonstd_fs runs one per path.
    if (open (my $outfh, '-|', $STAT, '-f', '-c', '%T %n', @candidates)) {
	while (my $line = <$outfh>) {
	    chomp ($line);
	    $fs_type{$2} = $1 if ($line =~ /^(\S+) (.*)\z/s);
	}
	close ($outfh);
    }
    my @checkable;
    foreach my $path (@candidates) {
	next unless (defined ($fs_type{$path}));          # left to _get_file_flags
	if (_nonstd_fs_type ($fs_type{$path})) {
	    $FLAGS_CACHE{$path} = '<undefined>';          # what _get_file_flags gives
	}
	else {
	    push (@checkable, $path);
	}
    }
    return unless (@checkable);
    my %wanted = map { $_ => 1 } @checkable;
    open (my $outfh, '-|', $LSATTR, $LSATTR_FLAGS_OPT, @checkable) or return;
    while (my $line = <$outfh>) {
	chomp ($line);
	next unless ($line =~ /^(\S+) (.*)\z/s && $wanted{$2});
	my ($flags, $path) = ($1, $2);
	$flags = 'none' if ($flags =~ /^[-]+$/);
	$FLAGS_CACHE{$path} = $flags;
    }
    close ($outfh);
}

# Subroutine to tell if a file is on a fuse or msdos filesystem (where
# Linux lsattr won't work). (This code was in two places, here in FileAttr
# and also above with immutable_file, which now calls FileAttr's _get_file_flags
# instead.)
sub _on_nonstd_fs {
    my ($file) = @_;
    my $fs_type;

    open (my $outfh, '-|', $STAT, '-f', '-c', '%T', $file);
    $fs_type = <$outfh>;
    close ($outfh);
    chomp ($fs_type) if (defined ($fs_type));
    return _nonstd_fs_type ($fs_type);
}

# Subroutine to tell if a stat -f %T filesystem type is one where Linux
# lsattr won't work (shared by _on_nonstd_fs and _prefetch_linux_flags).
sub _nonstd_fs_type {
    my ($fs_type) = @_;

    return 0 unless (defined ($fs_type));
    return 1 if ($fs_type eq 'fuse' || $fs_type eq 'msdos' ||
		 $fs_type eq 'tmpfs' || $fs_type eq 'mqueue' ||
		 $fs_type eq 'hugetlbfs' || $fs_type eq 'proc' ||
		 $fs_type eq 'devpts');
#    return 1 if ($fs_type ne 'ext2/ext3');
    return 0;
}

# Internal method to compare one field of a FileAttr record
# to another.  Returns 1 if fields are different, 0 if the same.
sub _compare {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($field1, $field2) = @_;

    if (!defined ($field1)) {
	return 1 if (defined ($field2));
	return 0;
    }
    elsif (!defined ($field2)) {
	return 1;
    }

    return 1 if ($field1 ne $field2);
    return 0;
}

# Internal method to compare a file's mtime to the current time,
# returning 1 if the duration is greater than the stasis period.
sub _mtime_stasis_greater {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($mtime, $mtimestasis) = @_;
    my ($duration, $number, $units);
    
    $duration = time() - $mtime;

    ($number, $units) = split (/,/, $mtimestasis);

    if ($units ne 's') { # we already have seconds 
	$duration = $duration / 60; # now have minutes
	if ($units ne 'm') {
	    $duration = $duration / 60; # now have hours
	    if ($units ne 'h') {
		$duration = $duration / 24; # now have days
	    }
	}
    }

    if ($duration > $number) {
	return 1;
    }
    else {
	return 0;
    }
}

# Method to compare one FileAttr record to another, putting the
# differences into hash.  We only compare attributes specified
# by keywords.
# $self is the saved (old) file structure; $fileattr is the current file structure.
sub compare {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($fileattr, $keywords_string) = @_;
    my (@keywords_array, $keyword, %keywords, %differences, %count, $file,
	@deleted_files, @added_files);

    %differences = ();

    # Keywords monitored are flags set to 1, except for the special-cased
    # mtimestasis-\d{1,2}[smhd] keyword, which we call just mtimestasis
    # and store the max time of stasis.
    @keywords_array = split (/,\s*/, $keywords_string);
    foreach $keyword (@keywords_array) {
	if ($keyword =~ /mtimestasis-(\d{1,2})([smhd])/) {
	    $keywords{'mtimestasis'} = "$1,$2";
	}
	else {
	    $keywords{$keyword} = 1;
	}
    }

    return (%differences) if ($keywords{'ignore'});

    if (($self->{TYPE} eq 'nonexistent') && ($fileattr->{TYPE} ne 'nonexistent')) {
	$differences{'added'} = 1;
	$differences{'type'} = $fileattr->{TYPE};
	$differences{'any'} = 1;
	return (%differences);
    }
    # The spec type is nonexistent and the item is nonexistent in the file system.
    # This can happen, for example, when using check_file for a nonexistent file.
    elsif ($self->{TYPE} eq 'nonexistent') {
	$differences{'any'} = 0;
	return (%differences);
    }
    elsif (defined ($fileattr->{TYPE}) && $fileattr->{TYPE} eq 'nonexistent') {
	$differences{'deleted'} = 1;
	$differences{'any'} = 1;
	# If this was a dir, all of its contents are also deleted.
	foreach $file (@{$self->{FILES}}) {
	    push (@deleted_files, $file);
	}
	$differences{'deleted_files'} = \@deleted_files if ($#deleted_files >= 0);
	return (%differences);
    }

    if ($keywords{'type'} && ($self->_compare ($self->{TYPE}, $fileattr->{TYPE}))) {
	$differences{'type'} = $fileattr->{TYPE};
	$differences{'any'} = 1;
    }
    # If filetype changes to or from a link, we still allow this comparison to go through--that
    # will yield either an old or new linktarget_type as "<undefined>".
    if ($keywords{'linktarget_type'} && (defined ($self->{LINKTARGET_TYPE}) && $self->_compare ($self->{LINKTARGET_TYPE}, $fileattr->{LINKTARGET_TYPE}))) {
	$differences{'linktarget_type'} = $fileattr->{LINKTARGET_TYPE};
	$differences{'any'} = 1;
    }
    if ($keywords{'mode'} && ($self->_compare ($self->{MODE}, $fileattr->{MODE}))) {
	$differences{'mode'} = $fileattr->{MODE};
	$differences{'any'} = 1;
    }
    if ($keywords{'uid'} && ($self->_compare ($self->{UID}, $fileattr->{UID}))) {
	$differences{'uid'} = $fileattr->{UID};
	$differences{'any'} = 1;
    }
    if ($keywords{'gid'} && ($self->_compare ($self->{GID}, $fileattr->{GID}))) {
	$differences{'gid'} = $fileattr->{GID};
	$differences{'any'} = 1;
    }
    # Only if the spec has a device number: specs from before 1.30 have
    # none, and re-initializing a tree records them.
    if ($keywords{'rdev'} && defined ($self->{RDEV}) &&
	($self->_compare ($self->{RDEV}, $fileattr->{RDEV}))) {
	$differences{'rdev'} = $fileattr->{RDEV} // '(none)';
	$differences{'any'} = 1;
    }
    if ($keywords{'size'} && ($self->_compare ($self->{SIZE}, $fileattr->{SIZE}))) {
	$differences{'size'} = $fileattr->{SIZE};
	$differences{'any'} = 1;
    }
    if ($keywords{'mtime'} && ($self->_compare ($self->{MTIME}, $fileattr->{MTIME}))) {
	$differences{'mtime'} = $fileattr->{MTIME};
	$differences{'any'} = 1;
    }
    if ($keywords{'mtimestasis'} && !($self->_compare ($self->{MTIME}, $fileattr->{MTIME})) &&
	$self->_mtime_stasis_greater ($fileattr->{MTIME}, $keywords{'mtimestasis'})) {
	$differences{'mtimestasis'} = $keywords{'mtimestasis'};
	$differences{'any'} = 1;
	# We now set $differences{'any'} = 1 because lack of change for critical logs counts
	# as a change.
    }
    if ($keywords{'ctime'} && ($self->_compare ($self->{CTIME}, $fileattr->{CTIME}))) {
	$differences{'ctime'} = $fileattr->{CTIME};
	$differences{'any'} = 1;
    }
    if ($keywords{'nlink'} && ($self->_compare ($self->{NLINK}, $fileattr->{NLINK}))) {
	$differences{'nlink'} = $fileattr->{NLINK};
	$differences{'any'} = 1;
    }

    if (($keywords{'sha2digest'} || $keywords{'sha3digest'} || $keywords{'shadigest'}) &&
	($self->{TYPE} eq 'file') &&
	($fileattr->{TYPE} eq 'file') &&
	($self->_compare ($self->{SHADIGEST}, $fileattr->{SHADIGEST}))) {
	$differences{'shadigest'} = $fileattr->{SHADIGEST};
	$differences{'any'} = 1;
    }
    if ($keywords{'flags'} &&
	($self->_compare ($self->{FLAGS}, $fileattr->{FLAGS}))) {
	$differences{'flags'} = $fileattr->{FLAGS};
	$differences{'any'} = 1;
    }
    if ($keywords{'link'} &&
	($self->{TYPE} eq 'link' && $fileattr->{TYPE} eq 'link' &&
	 $self->_compare ($self->{LINK}, $fileattr->{LINK}))) {
	$differences{'link'} = $fileattr->{LINK};
	$differences{'any'} = 1;
    }
    # If type hasn't changed, but they are both dirs, then contents
    # of the dir could have changed.
    # (Check for whether LINKTARGET_TYPE is defined is for backwards
    # compatibility with old specs.)
    if (($self->{TYPE} eq 'dir' || (defined ($self->{LINKTARGET_TYPE}) && ($self->{TYPE} eq 'link' && $self->{LINKTARGET_TYPE} eq 'dir'))) &&
	($fileattr->{TYPE} eq 'dir' || (defined ($fileattr->{LINKTARGET_TYPE}) && ($fileattr->{TYPE} eq 'link' && $fileattr->{LINKTARGET_TYPE} eq 'dir')))) {
	%count = ();
	foreach $file (@{$self->{FILES}}, @{$fileattr->{FILES}}) {
	    $count{$file}++;
	}
	foreach $file (@{$self->{FILES}}) {
	    push (@deleted_files, $file) if ($count{$file} == 1);
	}
	# Redundant, since we find added files as we hit them--we walk
	# the new structure, not the old one.
	# foreach $file (@{$fileattr->{FILES}}) {
	#    push (@added_files) if ($count{$file} == 1);
	# }
	$differences{'deleted_files'} = \@deleted_files if ($#deleted_files >= 0);
	# $differences{'added_files'} = \@added_files;
	# $differences{'any'} = 1 if ($#deleted_files >= 0);
    }
    # If it used to be a dir and now it isn't, then all of its
    # files have been deleted.
    elsif ($self->{TYPE} eq 'dir' || (defined ($self->{LINKTARGET_TYPE}) && ($self->{TYPE} eq 'link' && $self->{LINKTARGET_TYPE} eq 'dir'))) {
	foreach $file (@{$self->{FILES}}) {
	    push (@deleted_files, $file);
	}
	$differences{'deleted_files'} = \@deleted_files if ($#deleted_files >= 0);
    }
    # If it wasn't a dir but now it is, then all of its files have
    # been added.  But we'll be walking that structure automatically,
    # so we don't need to do anything special here.

    return (%differences);
}

# Method to display differences between two FileAttr records
# that have been compared.
sub display_diffs {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($primary_set, $priority, %differences) = @_;
    my ($display_path, 	@deleted_files, $file);

    if ($self->{PATH} eq $self->{TREE}) {
	if ($self->{TYPE} eq 'dir') {
	    $display_path = '.';
	}
	else {
	    $display_path = File::Basename::basename ($self->{PATH});
	}
    }
    else {
	$display_path = $self->{PATH};
    }
    print "\n   " . AttrDisplay::esc ($display_path) . " (set $primary_set, priority $priority)\n";
    if ($differences{'added'}) {
	if ($differences{'type'} eq 'nonexistent') {
	    print "   new file was added but has subsequently been deleted.\n";
	}
	else {
	    print "   new $differences{'type'} added.\n";
	}
	return;
    }
    elsif ($differences{'deleted'}) {
	print "   $self->{TYPE} deleted.\n";
    }

    # Each change in its long form, as changes -v shows it for a named
    # path (AttrDisplay).
    foreach my $attr (AttrDisplay::attrs ()) {
	next unless ($differences{$attr});
	next if ($attr eq 'mtimestasis' && $differences{'mtime'});
	print map { "$_\n" } AttrDisplay::long_lines ($attr, $self->{AttrDisplay::field ($attr)},
						       $differences{$attr});
    }
}

# Method to display a FileAttr record.
sub display {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($mode, $mtime, $ctime);

    print "tree: $self->{TREE}\n";
    print "path: $self->{PATH}\n";
    print "type: $self->{TYPE}\n";
    return if ($self->{TYPE} eq 'nonexistent');
    $mtime = localtime ($self->{MTIME});
    print "modification time: $mtime\n";
    $ctime = localtime ($self->{CTIME});
    print "inode change time: $ctime\n";
    $mode = sprintf "%0lo", $self->{MODE};
    $mode = substr ($mode, 2, 4);
    print "mode: $mode\n";
    print "uid: $self->{UID}\n";
    print "gid: $self->{GID}\n";
    print "nlink: $self->{NLINK}\n";
    print "size: $self->{SIZE}\n";
    print "shadigest: $self->{SHADIGEST}\n" if ($self->{TYPE} eq 'file' && defined ($self->{SHADIGEST}));
    print "flags: $self->{FLAGS}\n";
    print "device: " . device_number ($self->{RDEV}) . "\n" if (defined ($self->{RDEV}));
    print "link to: $self->{LINK}\n" if ($self->{TYPE} eq 'link');
    print "files: @{$self->{FILES}}\n" if ($self->{TYPE} eq 'dir');
}

1;

### End FileAttr package.

### Spec package.

# Methods to store information for an entire tree in a specification.
# new/add/get call FileAttr->new which requires $use_privsep global
# variable from main program.
package Spec;

use strict;
use warnings;
use Storable qw(fd_retrieve lock_retrieve nstore_fd);

# Method to create new spec or restore one from a saved file.
sub new {
    my $class = shift;
    my ($tree, $spec_path) = @_;
    my ($self, $fileattr);

    if (!defined ($spec_path)) {
        $self->{TREE} = $tree;
	$fileattr = new FileAttr ($tree, '.', $config->path_sha_digest ($tree, '.'));
	${$self->{FILEATTR}}{$tree} = $fileattr;
    }
    else {
	if ($main::use_privsep) {
	    # Requires privileged read.
	    my $fh = PrivSep::request_open ($FileAttr::PRIV_IPC, $spec_path);
	    if ($fh) {
		# Use fd_retrieve to read from the filehand.e
		$self = fd_retrieve ($fh);
		close ($fh);
	    }
	    else {
		warn "Failed to open spec file via privep: $spec_path\n";
		return (undef, undef);
	    }
	}
	else {
	    $self = lock_retrieve ($spec_path);
	    unless ($self) {
		warn "Failed to retrieve spec file: $spec_path\n";
		return (undef, undef);
	    }
	}
	$fileattr = ${$self->{FILEATTR}}{$tree};
        if (!defined ($fileattr)) {
	    print "Unable to retrieve fileattr for tree $tree from specification. $spec_path\nContinuing. Try re-initializing the specification if necessary.\n";
	    $self->{TREE} = $tree;
	    $fileattr = new FileAttr ($tree, '.', $config->path_sha_digest ($tree, '.'));
	    ${$self->{FILEATTR}}{$tree} = $fileattr;    
        }
    }

    bless $self, $class;
    return ($self, $fileattr);
}

# Method to add a path/FileAttr to a spec.
# Don't special-case the tree itself because it must already exist
# and can't be added to an existing spec.
sub add {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree, $path) = @_;
    my ($fileattr);

    $fileattr = new FileAttr ($tree, $path, $config->path_sha_digest ($tree, $path));
    ${$self->{FILEATTR}}{$path} = $fileattr;

    return ($fileattr);
}

# Method to update a path/FileAttr in a spec.
sub update {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree, $path, $fileattr) = @_;

    if ($path eq '.') {
	${$self->{FILEATTR}}{$tree} = $fileattr;
    }
    else {
        ${$self->{FILEATTR}}{$path} = $fileattr;
    }
}

# Method to return a FileAttr from a spec.
sub get {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($path) = @_;
    my ($fileattr);

    $fileattr = ${$self->{FILEATTR}}{$path};
    # If there is no fileattr for this path, create a special "nonexistent" type
    # fileattr.
    if (!defined ($fileattr)) {
        $fileattr = new FileAttr ($self->{TREE}, $path, $config->path_sha_digest ($self->{TREE}, $path), 1);
    }
    return $fileattr;
}

# Method to delete a path/FileAttr from a spec.
# Its children need to be deleted, which isn't currently done.
sub delete {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree, $path) = @_;
    my ($parent_path);

    if ($path eq '.') {
	delete (${$self->{FILEATTR}}{$tree});
    }
    else {
        delete (${$self->{FILEATTR}}{$path});
    }
}
1;

# Method to prepare to store a spec to a file.
sub store_spec {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($spec_path) = @_;

    # If hostname only has one component, respect that.
    if (!defined ($DOMAIN)) {
	$self->{HOST} = $HOSTNAME;
    }
    else {
	$self->{HOST} = $HOSTNAME . '.' . $DOMAIN;
    }
    $self->{TIME} = time();
    $self->{USER} = $USERNAME;

    if ($main::use_privsep) {
	# Request privileged open for writing
	my $fh = PrivSep::request_open ($FileAttr::PRIV_IPC,
					$spec_path,
					'>');
	unless ($fh) {
	    die "Failed to open spec file for writing via privsep: $spec_path\n";
	}
	nstore_fd ($self, $fh) or die "Failed to store spec to $spec_path: $!\n";
	close ($fh) or die "Failed to store spec to $spec_path: $!\n";
    }
    else {
	# Use main::safe_open_for_write for symlink protection
	my $fh = main::safe_open_for_write ($spec_path, 1) # 1 = needs lock
	    or die "Failed to open spec file $spec_path: $!\n";
	nstore_fd ($self, $fh) or die "Failed to store spec to $spec_path: $!\n";
	close ($fh) or die "Failed to store spec to $spec_path: $!\n";
    }
}

# Method to return hostname and creation time for a spec.
sub get_info {
    my $self = shift;
    my $class = ref ($self) || $self;

    return ($self->{HOST}, $self->{TIME}, $self->{USER});
}

### End Spec package.

### ChangedFile package.

# Methods to create and update changed file--list of trees and paths
# within each tree found to have been changed, along with times that
# checks were run.
# Possible addition to make:  Track the specific changes made to
# each object, and note them in the summary report instead of noting
# them when the changes are discovered (unless being verbose).  Could
# do this by storing a hash from $tree/$path to a %differences hash.
# (But we don't want to also store the original FileAttr, too...)
# This will be necessary for adding the feature of being able to look
# only at new changes since the last check.
#
# There is a primary and secondary changed file, as well as child
# changed files created by check in the /tmp dir. The first two require
# privileges to read and write but the /tmp ones are owned by the
# unprivileged child process.
package ChangedFile;

use strict;
use warnings;
use Storable qw(fd_retrieve lock_retrieve nstore_fd retrieve);

# Method to create a new changed file or read in its contents,
# and reset counters for check.
sub new {
    my $class = shift;
    my ($self);
    # $is_temp_file: a worker's own temp changed file, read and written
    # directly by the worker (never the main changed file). Given by the
    # caller rather than guessed from the path, so a root dir under /tmp
    # is not mistaken for one.
    my ($changed_file, $is_temp_file) = @_;
    $is_temp_file = $is_temp_file ? 1 : 0;

    # Might be a zero-length temp file.
    my $should_read = ((!$main::use_privsep && -e $changed_file && !-z $changed_file) ||
		       ($main::use_privsep && $is_temp_file && -e $changed_file && !-z $changed_file) ||
		       ($main::use_privsep && !$is_temp_file && grep { $_ eq $changed_file } @EXISTING_SPECS));

    if ($should_read) {
	if ($main::use_privsep && !$is_temp_file) {
	    # Main changed file, requires privileged read.
	    my $fh = PrivSep::request_open ($FileAttr::PRIV_IPC,
					    $changed_file);
	    if ($fh) {
		$self = fd_retrieve ($fh);
		close ($fh);
		unless ($self) {
		    warn "Failed to retrieve changed file from $changed_file\n";
		    $self = _initialize_empty_changedfile ($changed_file);
		}
	    }
	}
	elsif ($is_temp_file) {
	    # No locking on child temp files.
	    $self = retrieve ($changed_file);
	}
	else {
	    $self = lock_retrieve ($changed_file);
	}

	# Could not open or read it (the reason has been reported).
	return undef unless ($self);

	# Always use the current path, not what's serialized
	# (handles case where file was moved or path config changed)
	$self->{CHANGEDFILE} = $changed_file;
	# A changed file from before 1.31 has no values.
	$self->{SET_TO_PATH_CH_VALUES} //= {};
    }
    else {
	$self = _initialize_empty_changedfile ($changed_file);
    }
    $self->{IS_TEMP} = $is_temp_file;

    bless $self, $class;
    return $self;
}

# Helper method to initialize empty changedfile components.
sub _initialize_empty_changedfile {
    my ($changed_file) = @_;
    my $self = {};
    
    $self->{CHANGEDFILE} = $changed_file;
    $self->{CHANGES} = {};
    $self->{ADDITIONS} = {};
    $self->{DELETIONS} = {}; 
    $self->{SET_TO_PATH_ADD} = {}; 
    $self->{SET_TO_PATH_DEL} = {}; 
    $self->{SET_TO_PATH_CHANGE} = {}; 
    $self->{SET_TO_PATH_CH_ATTR} = {};
    $self->{SET_TO_PATH_CH_VALUES} = {};
    $self->{PATH} = {};
    
    return $self;
}

# Method to reset the changed file in preparation for recreating it.
sub reset_changed_file {
    my $self = shift;
    my $class = ref ($self) || $self;

    $self->{CHANGES} = {};
    $self->{ADDITIONS} = {};
    $self->{DELETIONS} = {};
    $self->{SET_TO_PATH_ADD} = {};
    $self->{SET_TO_PATH_DEL} = {};
    $self->{SET_TO_PATH_CHANGE} = {};
    $self->{SET_TO_PATH_CH_ATTR} = {};
    $self->{SET_TO_PATH_CH_VALUES} = {};
    $self->{PATH} = {};
    $self->{PATH_INDEX} = {};
    # don't reset TIME and USER
}

# Method to add a path to the changed file (unless already present).
# Update counters for changes for this check.  Set is primary set. $old
# is the path's FileAttr from the spec: for a changed path, each changed
# attribute's value in the spec and the value found are stored (since
# 1.31), so that the summary and changes can show them.
sub add {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree, $path, $set, $old, %differences) = @_;
    my ($full_path, $changed_attrs, @attrs);

    if ($path eq '.') {
	$full_path = $tree;
    }
    else {
	$full_path = $tree . '/' . $path;
    }

    if ($differences{'added'}) {
        ${$self->{ADDITIONS}}{'_total_'}++;
        ${$self->{ADDITIONS}}{$set}++;
        push (@{${$self->{SET_TO_PATH_ADD}}{$set}}, "$full_path");
    }
    elsif ($differences{'deleted'}) {
	${$self->{DELETIONS}}{'_total_'}++;
        ${$self->{DELETIONS}}{$set}++;
        push (@{${$self->{SET_TO_PATH_DEL}}{$set}}, "$full_path");
    }
    else {
        ${$self->{CHANGES}}{'_total_'}++;
        ${$self->{CHANGES}}{$set}++;
        push (@{${$self->{SET_TO_PATH_CHANGE}}{$set}}, "$full_path");
        @attrs = grep { exists ($differences{$_}) } AttrDisplay::attrs ();
        $changed_attrs = join (',', @attrs);
        push (@{${$self->{SET_TO_PATH_CH_ATTR}}{$set}}, $changed_attrs);
        push (@{${$self->{SET_TO_PATH_CH_VALUES}}{$set}},
	      { map { ($_ => [ ($old ? $old->{AttrDisplay::field ($_)} : undef),
			       $differences{$_} ]) } @attrs });
    }


    # Is the path already listed? A hash beside each tree's list answers
    # that at once; scanning the list made recording N changes N*N/2
    # comparisons (an hour or more after a major OS upgrade). The index is
    # rebuilt whenever the list has changed under it (merge, delete,
    # keep_only, a changed file just read from disk), and is not
    # stored (store_changedfile).
    my $list = (${$self->{PATH}}{$tree} //= []);
    my $index = ${$self->{PATH_INDEX}}{$tree};
    if (!$index || $index->{COUNT} != scalar (@{$list})) {
	$index = { SEEN => { map { ($_ => 1) } @{$list} },
		   COUNT => scalar (@{$list}) };
	${$self->{PATH_INDEX}}{$tree} = $index;
    }
    return if (${$index->{SEEN}}{$path});

    push (@{$list}, $path);
    ${$index->{SEEN}}{$path} = 1;
    $index->{COUNT}++;
}

# Method to add a new check time (and user) for a particular tree.
sub add_time {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree) = @_;

    push (@{${$self->{TIME}}{$tree}}, time());
    push (@{${$self->{USER}}{$tree}}, $USERNAME);
}

# Method to return an independent copy of this changed file (so check
# can keep a tree's previous results after resetting the original).
sub copy {
    my $self = shift;

    return Storable::dclone ($self);
}

# Method to merge a changed file with the main changed file.
# In current usage it should only be a single-set/single-tree changed
# file, but this is written more generally.
sub merge {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($other) = @_;
    my ($set);
    my (@trees, $tree);

    # Merge total and per-set additions, deletions, changes.
    foreach $set (keys (%{$other->{ADDITIONS}})) {
	if (${$other->{ADDITIONS}}{$set}) {
	    ${$self->{ADDITIONS}}{$set} +=  ${$other->{ADDITIONS}}{$set};
	    push (@{${$self->{SET_TO_PATH_ADD}}{$set}}, @{${$other->{SET_TO_PATH_ADD}}{$set}}) unless ($set eq '_total_');
	}
    }
    foreach $set (keys (%{$other->{DELETIONS}})) {
	if (${$other->{DELETIONS}}{$set}) {
	    ${$self->{DELETIONS}}{$set} +=  ${$other->{DELETIONS}}{$set};
	    push (@{${$self->{SET_TO_PATH_DEL}}{$set}}, @{${$other->{SET_TO_PATH_DEL}}{$set}}) unless ($set eq '_total_');
	}
    }
    foreach $set (keys (%{$other->{CHANGES}})) {
	if (${$other->{CHANGES}}{$set}) {
	    ${$self->{CHANGES}}{$set} +=  ${$other->{CHANGES}}{$set};
	    push (@{${$self->{SET_TO_PATH_CHANGE}}{$set}}, @{${$other->{SET_TO_PATH_CHANGE}}{$set}}) unless ($set eq '_total_');
	    push (@{${$self->{SET_TO_PATH_CH_ATTR}}{$set}}, @{${$other->{SET_TO_PATH_CH_ATTR}}{$set}}) unless ($set eq '_total_');
	    # Values, kept parallel to the paths.
	    unless ($set eq '_total_') {
		my $count = scalar (@{${$other->{SET_TO_PATH_CHANGE}}{$set}});
		my $values = ${$other->{SET_TO_PATH_CH_VALUES} || {}}{$set} || [];
		push (@{${$self->{SET_TO_PATH_CH_VALUES}}{$set}}, @{$values}[0 .. $count - 1]);
	    }
        }
    }

    # Get trees. Should be only one but this is more general.
    @trees = keys (%{$other->{PATH}});

    # Add trees and check times and users for each tree.
    foreach $tree (@trees) {
	push (@{${$self->{PATH}}{$tree}}, @{${$other->{PATH}}{$tree}});
	push (@{${$self->{TIME}}{$tree}}, @{${$other->{TIME}}{$tree} || []});
	push (@{${$self->{USER}}{$tree}}, @{${$other->{USER}}{$tree} || []});
    }
}

# Method to return array of changed sets, ordered from highest
# to lowest priority, along with total number of changes, additions,
# and deletions found in this check.
# This method uses a $config (Config) object, set_info method.
sub get_sets {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($changes, $additions, $deletions, %changed_sets,
	@sets, $set, $priority, $keywords, $description, %priorities);

    $changes = ${$self->{CHANGES}}{'_total_'} || 0;
    $additions = ${$self->{ADDITIONS}}{'_total_'} || 0;
    $deletions = ${$self->{DELETIONS}}{'_total_'} || 0;

    foreach $set (keys (%{$self->{CHANGES}})) {
        $changed_sets{$set} = 1;
    }
    foreach $set (keys (%{$self->{ADDITIONS}})) {
        $changed_sets{$set} = 1;
    }
    foreach $set (keys (%{$self->{DELETIONS}})) {
        $changed_sets{$set} = 1;
    }

    @sets = grep (!/^_total_$/, keys (%changed_sets));

    foreach $set (@sets) {
	($description, $keywords, $priority) = $config->set_info ($set);
	$priorities{$set} = $priority;
    }
    @sets = sort { $priorities{$b} <=> $priorities{$a} } @sets;
    return ($changes, $additions, $deletions, @sets);
}

# Method to return priority, description, number of total changed
# objects, number of added objects, and number of deleted objects
# for a set.
# This method uses a $config (Config) object, set_info method.
sub get_set_info {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($set) = @_;
    my ($description, $keywords, $priority,
	$changes, $additions, $deletions);

    ($description, $keywords, $priority) = $config->set_info ($set);
    $changes = ${$self->{CHANGES}}{$set} || 0;
    $additions = ${$self->{ADDITIONS}}{$set} || 0;
    $deletions = ${$self->{DELETIONS}}{$set} || 0;

    return ($priority, $description, $changes, $additions, $deletions);
}

# Method to get array of additions for a set.
sub get_set_additions {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($set) = @_;
    my ($additions, @paths);

    $additions = ${$self->{ADDITIONS}}{$set} || 0;
    if ($additions > 0) {
        @paths = @{${$self->{SET_TO_PATH_ADD}}{$set}};
    }
    else {
        @paths = ();
    }

    return (@paths);
}

# Method to get array of deletions for a set.
sub get_set_deletions {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($set) = @_;
    my ($deletions, @paths);

    $deletions = ${$self->{DELETIONS}}{$set} || 0;
    if ($deletions > 0) {
        @paths = @{${$self->{SET_TO_PATH_DEL}}{$set}};
    }
    else {
        @paths = ();
    }

    return (@paths);
}

# Method to get array of changes for a set.
sub get_set_changes {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($set) = @_;
    my ($changes, @paths);

    $changes = ${$self->{CHANGES}}{$set} || 0;
    if ($changes > 0) {
        @paths = @{${$self->{SET_TO_PATH_CHANGE}}{$set}};
    }
    else {
        @paths = ();
    }

    return (@paths);
}

# Method to get array of changed attributes for paths in a set.
sub get_set_changed_attrs {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($set) = @_;
    my ($changes, @attrs);

    $changes = ${$self->{CHANGES}}{$set} || 0;
    if ($changes > 0) {
        @attrs = @{${$self->{SET_TO_PATH_CH_ATTR}}{$set}};
    }
    else {
        @attrs = ();
    }

    return (@attrs);
}

# Method to get array of changed attributes' values for paths in a set,
# parallel to get_set_changes: for each path, a hash of attribute =>
# [value in the spec, value found by the check], or undef if the changed
# file is from before 1.31.
sub get_set_changed_values {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($set) = @_;
    my ($changes, $values);

    $changes = ${$self->{CHANGES}}{$set} || 0;
    return () unless ($changes > 0);
    $values = ${$self->{SET_TO_PATH_CH_VALUES} || {}}{$set} || [];
    return (@{$values}[0 .. $#{${$self->{SET_TO_PATH_CHANGE}}{$set}}]);
}

# Method to return the pending paths of the trees in the changed file,
# sorted, one hash each: TREE, PATH (the full path), SET, KIND
# ('changed', 'added' or 'deleted'), and for a changed path ATTRS (a
# list of the changed attributes) and VALUES (as get_set_changed_values).
sub get_entries {
    my $self = shift;
    my $class = ref ($self) || $self;
    my (@trees, @entries, %sets);

    @trees = keys (%{$self->{PATH}});
    foreach my $lists ('SET_TO_PATH_ADD', 'SET_TO_PATH_DEL', 'SET_TO_PATH_CHANGE') {
	$sets{$_} = 1 foreach (keys (%{$self->{$lists} || {}}));
    }
    foreach my $set (keys (%sets)) {
	foreach my $path ($self->get_set_additions ($set)) {
	    push (@entries, { PATH => $path, SET => $set, KIND => 'added' });
	}
	foreach my $path ($self->get_set_deletions ($set)) {
	    push (@entries, { PATH => $path, SET => $set, KIND => 'deleted' });
	}
	my @paths = $self->get_set_changes ($set);
	my @attrs = $self->get_set_changed_attrs ($set);
	my @values = $self->get_set_changed_values ($set);
	foreach my $i (0 .. $#paths) {
	    push (@entries, { PATH => $paths[$i], SET => $set, KIND => 'changed',
			      ATTRS => [ split (/,/, $attrs[$i] // '') ],
			      VALUES => $values[$i] });
	}
    }
    # Each path's tree, the longest that holds it. A path of a tree no
    # longer in the changed file (a changed file from before 1.31, after
    # an update of some of its trees) is left out.
    foreach my $entry (@entries) {
	$entry->{TREE} = _path_tree ($entry->{PATH}, @trees);
    }
    return (sort { $a->{PATH} cmp $b->{PATH} } grep { defined ($_->{TREE}) } @entries);
}

# The tree, of those given, that holds a full path (the longest, since
# one tree may lie within another).
sub _path_tree {
    my ($path, @trees) = @_;
    my $best;

    foreach my $tree (@trees) {
	next unless ($path eq $tree || index ($path, ($tree eq '/') ? '/' : "$tree/") == 0);
	$best = $tree if (!defined ($best) || length ($tree) > length ($best));
    }
    return $best;
}

# Method to return an array of tree names in the changed file.
sub get_trees {
    my $self = shift;
    my $class = ref ($self) || $self;
    my (@trees);
    
    @trees = keys (%{$self->{PATH}});
    return (@trees);
}

# Method to return an array of pathnames for a specific tree in the
# changed file.
sub get_paths {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree) = @_;
    my (@paths);

    @paths = @{${$self->{PATH}}{$tree}};
    return (@paths);
}

# Method to return 1 if a given tree is in the changed file.
sub tree_present {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree) = @_;

    return (defined (${$self->{PATH}}{$tree}));
}

# Method to return 1 if a given path is in the changed file
# (relative to specified tree).
sub path_present {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree, $path) = @_;
    my (@paths, $tree_path);

    if (defined (${$self->{PATH}}{$tree})) {
        @paths = @{${$self->{PATH}}{$tree}};
        foreach $tree_path (@paths) {
	    return 1 if ($path eq $tree_path);
        }
    }
    return 0;
}

# Method to return array of check times for a specific tree in the
# changed file.
sub get_times {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree) = @_;
    my (@times);

    @times = @{${$self->{TIME}}{$tree} || []};
    return (@times);
}

# Method to return array of check users for a specific tree in the
# changed file.
sub get_users {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree) = @_;
    my (@users);

    @users = @{${$self->{USER}}{$tree} || []};
    return (@users);
}

# Method to delete a tree from the changed file.
sub delete {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree) = @_;

    # And the tree's paths from the per-set lists and counts, which
    # before 1.31 were left behind, so that after an update of some
    # trees, changes -v still listed the updated trees' paths.
    $self->keep_only (sub { $_[0] ne $tree });

    delete (${$self->{PATH}}{$tree});
    delete (${$self->{PATH_INDEX}}{$tree});
    delete (${$self->{TIME}}{$tree});
    delete (${$self->{USER}}{$tree});
}

# Method to keep only the records of the paths for which
# $keep->($tree, $full_path) is true: in the per-set lists (and their
# counts) and the per-tree path lists. Check times and users are kept.
# A path in a per-set list whose tree is no longer in the changed file
# (left by a version before 1.31) is dropped.
sub keep_only {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($keep) = @_;
    my @trees = keys (%{$self->{PATH}});

    foreach my $kind (['ADDITIONS', 'SET_TO_PATH_ADD'],
		      ['DELETIONS', 'SET_TO_PATH_DEL'],
		      ['CHANGES', 'SET_TO_PATH_CHANGE', 'SET_TO_PATH_CH_ATTR',
		       'SET_TO_PATH_CH_VALUES']) {
	my ($counts, $lists, @parallel) = @{$kind};
	foreach my $set (keys (%{$self->{$lists} || {}})) {
	    my $paths = ${$self->{$lists}}{$set};
	    my @keep = grep { my $tree = _path_tree ($paths->[$_], @trees);
			      defined ($tree) && $keep->($tree, $paths->[$_]) } (0 .. $#{$paths});
	    my $removed = scalar (@{$paths}) - scalar (@keep);
	    next unless ($removed);
	    foreach my $list ($lists, @parallel) {
		my $old = ${$self->{$list} || {}}{$set} || [];
		${$self->{$list}}{$set} = [ @{$old}[@keep] ];
	    }
	    ${$self->{$counts}}{$set} -= $removed;
	    ${$self->{$counts}}{'_total_'} -= $removed;
	    if (${$self->{$counts}}{$set} <= 0) {
		delete (${$self->{$counts}}{$set});
		delete (${$self->{$_}}{$set}) foreach ($lists, @parallel);
	    }
	}
    }
    foreach my $tree (@trees) {
	my @paths = grep { $keep->($tree, ($_ eq '.') ? $tree : "$tree/$_") } @{${$self->{PATH}}{$tree}};
	if (@paths) {
	    ${$self->{PATH}}{$tree} = \@paths;
	}
	else {
	    delete (${$self->{PATH}}{$tree});
	}
	delete (${$self->{PATH_INDEX}}{$tree});
    }
}

# Method to delete a worker's temp changed file if there are no changed
# trees left in it. Since 1.30 the main (primary or secondary) changed
# file is kept even when empty: callers store it first, so it always
# exists after a check, initialize or update, and its mtime is the time
# of the last of them (verify_hosts uses that). An empty one means
# nothing is pending.
sub delete_if_empty {
    my $self = shift;
    my $class = ref ($self) || $self;
    my (@trees);

    return unless ($self->{IS_TEMP});
    @trees = keys (%{$self->{PATH}});
    if ($#trees < 0) {
	unlink ($self->{CHANGEDFILE});
    }
}

# Method to store changed file. Stores even if empty.
sub store_changedfile {
    my $self = shift;
    my $class = ref ($self) || $self;

    my $is_temp_file = $self->{IS_TEMP};

    # The lookup index add keeps is rebuilt as needed, so it is not
    # written to disk.
    local $self->{PATH_INDEX};
    delete $self->{PATH_INDEX};

    if ($main::use_privsep && !$is_temp_file) {
	# Main changed file - requires privileged write.
	my $fh = PrivSep::request_open ($FileAttr::PRIV_IPC,
					$self->{CHANGEDFILE},
					'>');
	unless ($fh) {
	    die "Failed to open changed file for writing via privsep: $self->{CHANGEDFILE}\n";
	}
	(nstore_fd ($self, $fh) && close ($fh))
	    or die "Failed to store changed file $self->{CHANGEDFILE}: $!\n";
    }
    elsif ($is_temp_file) {
	# Worker temp file - no lock needed (each worker has its own).
	my $fh = main::safe_open_for_write ($self->{CHANGEDFILE}, 0) # 0 = no lock
	    or die "Failed to open temp changed file: $!\n";
	nstore_fd ($self, $fh)
	    or die "Failed to store child changed file: $!\n";
	close ($fh) or die "Failed to store child changed file: $!\n";
    }
    else {
	# Main changed file - needs lock.
	my $fh = main::safe_open_for_write ($self->{CHANGEDFILE}, 1) # 1 = needs lock
	    or die "Failed to open changed file: $!\n";
	nstore_fd ($self, $fh)
	    or die "Failed to store changed file: $!\n";
	close ($fh) or die "Failed to store changed file: $!\n";
    }
}

1;

### End ChangedFile package.

### AttrDisplay package.

# How a change in an attribute is shown, shared by check's per-path
# output (-v) and closing summary, changes, and the verify_hosts detail
# query. Attributes are named as in the changed file, by their sigtree
# keywords, and each is held in a FileAttr field. Nothing here is set up
# by the package body, which the main program never reaches (it exits
# first), so the tables are returned by subs.
package AttrDisplay;

use strict;
use warnings;
use POSIX ();

# The attributes, in the order they are shown.
sub attrs {
    return qw(type linktarget_type mode uid gid size mtime mtimestasis ctime
	      nlink shadigest flags rdev link);
}

# The FileAttr field an attribute is held in (for mtimestasis, the
# modification time that has not changed).
sub field {
    my ($attr) = @_;
    return ($attr eq 'mtimestasis') ? 'MTIME' : uc ($attr);
}

sub _label {
    my ($attr) = @_;
    my %label = (linktarget_type => 'link target type', mtime => 'modification time',
		 ctime => 'inode change time', rdev => 'device number',
		 link => 'symbolic link target');
    return $label{$attr} // $attr;
}

# Control characters escaped, so that a file name or link target cannot
# write to the terminal.
sub esc {
    my ($text) = @_;
    return '' unless (defined ($text));
    $text =~ s/([\x00-\x1f\x7f])/sprintf ('\\x%02x', ord ($1))/ge;
    return $text;
}

# The attributes that -k names, as sigtree keywords (sha2digest and
# sha3digest mean shadigest, and mtime includes mtimestasis). Dies on an
# unknown keyword.
sub keyword_attrs {
    my ($keywords) = @_;
    my %alias = (sha2digest => 'shadigest', sha3digest => 'shadigest');
    my %known = map { ($_ => 1) } grep { $_ ne 'mtimestasis' } attrs ();
    my %want;

    foreach my $keyword (split (/\s*,\s*/, $keywords)) {
	next if ($keyword eq '');
	my $attr = $alias{$keyword} // $keyword;
	die "Unknown keyword \"" . esc ($keyword) . "\" in -k (expected any of " .
	    join (',', sort (keys (%known), keys (%alias))) . ").\n" unless ($known{$attr});
	$want{$attr} = 1;
	$want{'mtimestasis'} = 1 if ($attr eq 'mtime');
    }
    die "No keywords given with -k.\n" unless (%want);
    return grep { $want{$_} } attrs ();
}

# The attributes shown: all of them, unless set_filter has named some.
our $FILTER;
sub set_filter {
    my (@attrs) = @_;
    $FILTER = { map { ($_ => 1) } @attrs };
}

sub shown {
    my (@attrs) = @_;
    return @attrs unless ($FILTER);
    return grep { $FILTER->{$_} } @attrs;
}

# Words for an mtimestasis limit ("2,d" is "two days").
sub _stasis {
    my ($limit) = @_;
    my %numbers = (1 => 'one', 2 => 'two', 3 => 'three', 4 => 'four', 5 => 'five',
		   6 => 'six', 7 => 'seven', 8 => 'eight', 9 => 'nine', 10 => 'ten');
    my %units = (s => 'second', m => 'minute', h => 'hour', d => 'day');
    my ($number, $unit) = split (/,/, $limit // '');
    return esc ($limit) unless (defined ($unit) && $units{$unit} && $number =~ /^\d+\z/);
    $unit = $units{$unit};
    $unit .= 's' if ($number > 1);
    $number = $numbers{$number} if ($number < 11 && $numbers{$number});
    return "$number $unit";
}

# A value as shown: modes as permission bits in octal, times as dates
# (in full with long), device numbers as major,minor (raw with raw_rdev:
# verify_hosts may be showing a spec from another OS), and digests cut
# to 12 characters with short.
sub value {
    my ($attr, $value, %opt) = @_;
    my $field = field ($attr);

    return '(none)' unless (defined ($value));
    if ($field eq 'MODE' && $value =~ /^\d+\z/) {
	return sprintf ('%04o', $value & 07777);
    }
    if (($field eq 'MTIME' || $field eq 'CTIME') && $value =~ /^\d+\z/) {
	return $opt{'long'} ? scalar (localtime ($value)) :
	    POSIX::strftime ('%Y-%m-%d %H:%M', localtime ($value));
    }
    if ($field eq 'RDEV' && !$opt{'raw_rdev'}) {
	return FileAttr::device_number ($value);
    }
    $value = esc ($value);
    if ($field eq 'SHADIGEST' && $opt{'short'} && length ($value) > 15) {
	return substr ($value, 0, 12) . '...';
    }
    return $value;
}

# One change, on one line: "mode 0644 -> 0600".
sub change {
    my ($attr, $old, $new, %opt) = @_;

    if ($attr eq 'mtimestasis') {
	return 'mtime unchanged since ' . value ('mtime', $old, %opt) .
	    ', more than ' . _stasis ($new);
    }
    my ($o, $n) = (value ($attr, $old, %opt), value ($attr, $new, %opt));
    # Two times in the same minute: with the seconds.
    if ($o eq $n && ($attr eq 'mtime' || $attr eq 'ctime') && !$opt{'long'}) {
	($o, $n) = map { /^\d+\z/ ? POSIX::strftime ('%Y-%m-%d %H:%M:%S', localtime ($_)) : value ($attr, $_) }
	    ($old, $new);
    }
    return "$attr $o -> $n";
}

# One change in check's long form: one line, or two when a value is
# long (a digest, a time or a link target), with the new value on the
# second.
sub long_lines {
    my ($attr, $old, $new) = @_;
    my $label = _label ($attr);
    my ($stasis, $indent);

    if ($attr eq 'mtimestasis') {
	$stasis = 1;
	$old = value ('mtime', $old, 'long' => 1);
	$new = _stasis ($new);
    }
    else {
	$old = value ($attr, $old, 'long' => 1);
	$new = value ($attr, $new, 'long' => 1);
    }

    if (length ($old) > 20 || length ($new) > 20) {
	$indent = '   ' . (' ' x (length ($label) + 14));
	return ("   modification time has not changed from $old for more than", "$indent$new")
	    if ($stasis);
	return ("   $label changed from $old to", "$indent$new");
    }
    return ("   modification time has not changed from $old for more than $new.") if ($stasis);
    return ("   $label changed from $old to $new.");
}

1;

### End AttrDisplay package.

### VerifyHosts package.

# The verify_hosts command, run on a server that collects other hosts'
# sigtree databases (rsynced copies under a spec root, and rsnapshot
# snapshots of each host's /var). It reports, for each host in its own
# config file:
#   - the age of the host's primary changed file (its mtime is the time
#     of the host's last check that found changes), or that there is none;
#   - spec files changed between the previous and current snapshots, and
#     any whose contents match an older snapshot instead of the previous
#     one (a validly signed old spec put back);
#   - for hosts with a signify key pinned in the config, any spec or
#     spec-of-specs whose signature does not verify;
#   - for hosts marked as peers, files under the configured common paths
#     that differ from what most peers have, are missing, or exist on one
#     host only.
# "verify_hosts <host> [spec | /path]" instead shows, on demand, what
# changed in each of that host's specs between the two snapshots (one
# spec, or one file, which with backups of both versions is shown as a
# diff).
# Specs are Storable files written by the hosts, so a spec is loaded only
# after its signature has verified, and only in a child process that has
# dropped to _sigtree. Nothing else a host wrote is deserialized: the
# changed file is judged by its mtime and the snapshots by size and hash.
# It prints nothing when there is nothing to report.
package VerifyHosts;

use strict;
use warnings;
use Digest::SHA;
use Digest::SHA3;
use File::Basename ();
use Fcntl qw( :DEFAULT O_NOFOLLOW :mode );
use POSIX ();
use Storable qw( fd_retrieve );

use constant DEFAULT_MAX_AGE => 36;          # hours
use constant DEFAULT_ATTRIBUTES => 'type,shadigest,mode,uid,gid,link';
use constant DEFAULT_SNAPSHOT_SUBDIR => 'var/db/sigtree';
use constant DEFAULT_CURRENT => 'daily.0';
use constant DEFAULT_PREVIOUS => 'daily.1';
use constant LIST_LIMIT => 25;               # lines per host per category
use constant DIFF => '/usr/bin/diff';
use constant DAY => 86400;

# Spec attribute names that can be compared, and the FileAttr field each
# one is stored in.
our %ATTR_FIELD;
our $LOAD_PROBLEM;     # why _load_spec refused a spec (1.32)

sub _attr_fields {
    %ATTR_FIELD = (type => 'TYPE', shadigest => 'SHADIGEST', mode => 'MODE',
		   uid => 'UID', gid => 'GID', link => 'LINK', size => 'SIZE',
		   flags => 'FLAGS', nlink => 'NLINK', rdev => 'RDEV') unless (%ATTR_FIELD);
}

# Entry point. Returns the exit status: 0 if nothing was reported, 1 if
# anything was.
sub run {
    my ($config_file, $verbose, $osname, $keywords, @args) = @_;
    my (@out, $reported);

    _attr_fields ();
    my $cf = _parse_config ($config_file);
    if (@args) {
	_set_show_fields ($verbose, $keywords);
	return _details ($cf, $verbose, $osname, @args);
    }

    _require_signify ();

    # Specs are only ever loaded as _sigtree.
    my ($uid, $gid) = ((getpwnam ('_sigtree'))[2], (getgrnam ('_sigtree'))[2]);
    # Hosts whose specs are needed beyond the peer comparison.
    my %chroot_host = map { $_ => 1 } (map { @{$_->{HOSTS}} } @{$cf->{CHROOTS}}),
	@{$cf->{REFERENCE_HOSTS}};
    if ((grep { $_->{PEER} } @{$cf->{HOSTS}}) || %chroot_host) {
	die "verify_hosts needs the _sigtree user and group to compare hosts or check chroots.\n"
	    unless (defined ($uid) && defined ($gid));
	die "verify_hosts must be run as root to compare hosts or check chroots.\n" if ($> != 0);
    }

    _restrict ($cf, $osname, 0);

    my $temp_dir = main::mkdtemp ('/tmp/sigtree.XXXXXXXX') or
	die "Could not create a temp dir: $!\n";
    my %verified;  # host => [ [name, data], ... ] for peers whose specs all verified
    my %chroot_specs;  # the same, for hosts with a chroot to check
    my %hash_cache;
    my $ok = eval {
	my $snapshots = _list_snapshots ($cf);
	foreach my $host (@{$cf->{HOSTS}}) {
	    my @lines;
	    push (@lines, _check_changed_file ($cf, $host));
	    push (@lines, _check_snapshots ($cf, $host, $snapshots, \%hash_cache))
		if (defined ($cf->{SNAPSHOT_ROOT}));
	    if (defined ($host->{KEY})) {
		my ($sig_lines, $specs, $all_good) = _check_signatures ($cf, $host, $temp_dir);
		push (@lines, @{$sig_lines});
		if ($all_good) {
		    $verified{$host->{NAME}} = $specs if ($host->{PEER});
		    $chroot_specs{$host->{NAME}} = $specs if ($chroot_host{$host->{NAME}});
		}
		else {
		    push (@lines, "not compared with peers: not every spec has a good signature")
			if ($host->{PEER});
		    push (@lines, "chroots and reference files not checked: not every spec has a good signature")
			if ($chroot_host{$host->{NAME}});
		}
	    }
	    else {
		push (@lines, "not compared with peers: no signify key in the config")
		    if ($host->{PEER});
		push (@lines, "chroots and reference files not checked: no signify key in the config")
		    if ($chroot_host{$host->{NAME}});
	    }
	    if (@lines) {
		push (@out, "$host->{NAME}:", map { "   $_" } @lines);
		$reported = 1;
	    }
	    elsif ($verbose) {
		push (@out, "$host->{NAME}: OK");
	    }
	}
	my @peer_lines = _compare_peers ($cf, \%verified, $uid, $gid, $osname);
	if (@peer_lines) {
	    push (@out, "Comparison of peers (" . join (', ', sort keys %verified) . "):",
		  map { "   $_" } @peer_lines);
	    $reported = 1;
	}
	elsif ($verbose && keys (%verified) >= 2) {
	    push (@out, "Comparison of peers (" . join (', ', sort keys %verified) . "): OK");
	}
	if (@{$cf->{REFERENCE}}) {
	    my $ref_digests = _reference_digests ($cf);
	    my @ref_lines = _in_child ($uid, $gid, $osname,
				       sub { _check_references ($cf, \%chroot_specs, $ref_digests) });
	    if (@ref_lines) {
		push (@out, "Reference files (" . join (', ', map { _esc ($_) } @{$cf->{REFERENCE}}) . "):",
		      map { "   $_" } @ref_lines);
		$reported = 1;
	    }
	    elsif ($verbose) {
		push (@out, "Reference files: OK");
	    }
	}
	if (@{$cf->{CHROOTS}} && %chroot_specs) {
	    my @chroot_lines = _in_child ($uid, $gid, $osname,
					  sub { _check_chroots ($cf, \%chroot_specs) });
	    if (@chroot_lines) {
		push (@out, @chroot_lines);
		$reported = 1;
	    }
	    elsif ($verbose) {
		push (@out, "Chroots (" . join (', ', map { $_->{ROOT} } @{$cf->{CHROOTS}}) . "): OK");
	    }
	}
	1;
    };
    my $error = $@;
    _remove_dir ($temp_dir);
    die $error unless ($ok);

    print "$_\n" foreach (@out);
    return ($reported ? 1 : 0);
}

sub _require_signify {
    main::require_module ('Signify') or
	die "Could not require Signify. $@\n";
    eval { Signify->VERSION ('1.4'); 1 } or
	die "Signify.pm " . (Signify->VERSION // 'without a version') .
	    " is too old, 1.4 or later is required.\n";
}

# pledge and unveil on OpenBSD: read the two roots (and any key copies),
# run signify (and diff, for the detail query), and use a private dir in
# /tmp. A child that loads specs drops to _sigtree and pledges only stdio.
sub _restrict {
    my ($cf, $osname, $need_diff) = @_;

    return unless ($osname eq 'openbsd');
    main::pledge ('rpath', 'wpath', 'cpath', 'proc', 'exec', 'id', 'unveil') ||
	die "Cannot pledge promises. $!\n";
    main::unveil ($cf->{SPEC_ROOT}, 'r');
    main::unveil ($cf->{SNAPSHOT_ROOT}, 'r') if (defined ($cf->{SNAPSHOT_ROOT}));
    foreach my $host (@{$cf->{HOSTS}}) {
	main::unveil ($host->{KEY_COPY}, 'r') if (defined ($host->{KEY_COPY}));
    }
    main::unveil ($_, 'r') foreach (@{$cf->{REFERENCE}});
    { no warnings 'once'; main::unveil ($Signify::SIGNIFY_PATH, 'rx'); }
    main::unveil (DIFF, 'rx') if ($need_diff);
    main::unveil ('/tmp', 'rwc');
    main::unveil ();
}

# Escape what a host wrote (file names, paths, link targets, file
# contents) before it is printed: control characters, including newline,
# as \xNN, so it cannot start a line or reach the terminal raw.
sub _esc {
    return AttrDisplay::esc (@_);
}

# Parse the verify_hosts config. "field: value" lines, # comments. Host
# settings (key, key-copy, peer) follow their "host:" line.
sub _parse_config {
    my ($config_file) = @_;
    my (%cf, $current, $chroot, $line_no);

    open (my $fh, '<', $config_file) ||
	die "Cannot open config file. $!. $config_file\n";
    my @stat = stat ($fh);
    die "Cannot stat config file. $!. $config_file\n" unless (@stat);
    die "Config file $config_file must not be group or world writable.\n"
	if ($stat[2] & 0022);
    die "Config file $config_file is not owned by root (uid=$stat[4]).\n"
	if ($stat[4] != 0 && $stat[4] != $>);

    $cf{HOSTS} = [];
    $cf{COMMON} = [];
    $cf{EXCEPT} = [];
    my %seen;
    while (my $raw = <$fh>) {
	$line_no++;
	my $l = $raw;
	$l =~ s/^\s+//;
	$l =~ s/\s+\z//;
	next if ($l eq '' || $l =~ /^#/);
	my ($field, $value) = ($l =~ /^([a-z-]+):\s*(.*)\z/);
	die "Unparseable line $line_no. $config_file\nLine: $raw" unless (defined ($field));
	die "No value for \"$field:\", line $line_no. $config_file\nLine: $raw" if ($value eq '');
	if ($field =~ /^(spec-root|snapshot-root)\z/) {
	    die "\"$field:\" must be an absolute path, line $line_no. $config_file\nLine: $raw"
		unless ($value =~ m{^/} && $value !~ m{(?:^|/)\.\.(?:/|\z)});
	    my $key = ($field eq 'spec-root') ? 'SPEC_ROOT' : 'SNAPSHOT_ROOT';
	    die "Second \"$field:\", line $line_no. $config_file\nLine: $raw" if (defined ($cf{$key}));
	    $cf{$key} = $value;
	}
	elsif ($field eq 'snapshot-subdir') {
	    die "\"snapshot-subdir:\" must be a relative path without \"..\", line $line_no. $config_file\nLine: $raw"
		if ($value =~ m{^/} || $value =~ m{(?:^|/)\.\.(?:/|\z)});
	    $cf{SNAPSHOT_SUBDIR} = $value;
	}
	elsif ($field =~ /^(current|previous)-snapshot\z/) {
	    my $which = uc ($1);    # before the match below resets $1
	    die "Invalid \"$field:\" (expected a name like daily.0), line $line_no. $config_file\nLine: $raw"
		unless ($value =~ /^[\w-]+\.\d+\z/);
	    $cf{$which} = $value;
	}
	elsif ($field eq 'previous-age') {
	    die "\"previous-age:\" must be a number of days, line $line_no. $config_file\nLine: $raw"
		unless ($value =~ /^\d+\z/ && $value > 0);
	    $cf{PREVIOUS_AGE} = $value;
	}
	elsif ($field eq 'max-age') {
	    die "\"max-age:\" must be a number of hours, line $line_no. $config_file\nLine: $raw"
		unless ($value =~ /^\d+\z/ && $value > 0);
	    $cf{MAX_AGE} = $value;
	}
	elsif ($field eq 'attributes') {
	    my @attrs = split (/\s*,\s*/, $value);
	    foreach my $attr (@attrs) {
		die "Unknown attribute \"$attr\" in \"attributes:\", line $line_no. $config_file\nLine: $raw"
		    unless ($ATTR_FIELD{$attr});
	    }
	    $cf{ATTRIBUTES} = \@attrs;
	}
	elsif ($field eq 'common' || $field eq 'except') {
	    foreach my $path (split (/\s+/, $value)) {
		die "\"$field:\" paths must be absolute, line $line_no. $config_file\nLine: $raw"
		    unless ($path =~ m{^/});
		$path =~ s{/+\z}{} unless ($path eq '/');
		push (@{$cf{uc ($field)}}, [$path, _glob_to_regex ($path)]);
	    }
	}
	elsif ($field eq 'host') {
	    die "Invalid host name \"$value\", line $line_no. $config_file\nLine: $raw"
		unless ($value =~ /^[\w][\w.-]*\z/);
	    die "Second \"host: $value\", line $line_no. $config_file\nLine: $raw" if ($seen{$value}++);
	    $current = { NAME => $value, PEER => 0 };
	    push (@{$cf{HOSTS}}, $current);
	}
	elsif ($field eq 'reference') {
	    foreach my $path (split (/\s+/, $value)) {
		die "\"reference:\" paths must be absolute, without \"..\" or patterns, line $line_no. $config_file\nLine: $raw"
		    unless ($path =~ m{^/[^/]} && $path !~ m{(?:^|/)\.\.(?:/|\z)} && $path !~ /[*?]/);
		push (@{$cf{REFERENCE}}, $path);
	    }
	}
	elsif ($field eq 'reference-hosts') {
	    push (@{$cf{REFERENCE_HOSTS}}, grep { $_ ne '' } split (/[\s,]+/, $value));
	}
	elsif ($field eq 'system-root') {
	    die "\"system-root:\" must be an absolute path, line $line_no. $config_file\nLine: $raw"
		unless ($value =~ m{^/} && $value !~ m{(?:^|/)\.\.(?:/|\z)});
	    $value =~ s{/+\z}{} unless ($value eq '/');
	    $cf{SYSTEM_ROOT} = $value;
	}
	elsif ($field eq 'chroot') {
	    die "\"chroot:\" must be an absolute path other than /, line $line_no. $config_file\nLine: $raw"
		unless ($value =~ m{^/[^/]} && $value !~ m{(?:^|/)\.\.(?:/|\z)});
	    $value =~ s{/+\z}{};
	    die "Second \"chroot: $value\", line $line_no. $config_file\nLine: $raw"
		if (grep { $_->{ROOT} eq $value } @{$cf{CHROOTS} || []});
	    $chroot = { ROOT => $value, HOSTS => [], MIRROR => [], MIRROR_EXCEPT => [],
			ALLOW_ONLY => [], ALLOW_EXTRA => [], RULES_EXCEPT => [], COMPARE_EXCEPT => [] };
	    push (@{$cf{CHROOTS}}, $chroot);
	}
	elsif ($field =~ /^(chroot-hosts|mirror|mirror-except|allow-only|allow-extra|rules-except|compare-except)\z/) {
	    die "\"$field:\" before any \"chroot:\", line $line_no. $config_file\nLine: $raw"
		unless (defined ($chroot));
	    if ($field eq 'chroot-hosts') {
		push (@{$chroot->{HOSTS}}, grep { $_ ne '' } split (/[\s,]+/, $value));
	    }
	    else {
		(my $key = uc ($field)) =~ s/-/_/g;
		foreach my $rel (split (/\s+/, $value)) {
		    die "\"$field:\" paths are relative to the chroot and without \"..\", line $line_no. $config_file\nLine: $raw"
			if ($rel =~ m{^/} || $rel =~ m{(?:^|/)\.\.(?:/|\z)});
		    $rel =~ s{/+\z}{};
		    if ($key eq 'MIRROR') {
			die "\"mirror:\" takes directories or files, not patterns, line $line_no. $config_file\nLine: $raw"
			    if ($rel =~ /[*?]/);
			push (@{$chroot->{MIRROR}}, $rel);
		    }
		    else {
			push (@{$chroot->{$key}}, [$rel, _glob_to_regex ("$chroot->{ROOT}/$rel")]);
		    }
		}
	    }
	}
	elsif ($field eq 'key' || $field eq 'key-copy' || $field eq 'peer') {
	    die "\"$field:\" before any \"host:\", line $line_no. $config_file\nLine: $raw"
		unless (defined ($current));
	    if ($field eq 'key') {
		die "Second \"key:\" for host $current->{NAME}, line $line_no. $config_file\nLine: $raw"
		    if (defined ($current->{KEY}));
		die "\"key:\" must be the base64 line of a signify public key, line $line_no. $config_file\nLine: $raw"
		    unless ($value =~ m{^[A-Za-z0-9+/]{40,}={0,2}\z});
		$current->{KEY} = $value;
	    }
	    elsif ($field eq 'key-copy') {
		die "\"key-copy:\" must be an absolute path, line $line_no. $config_file\nLine: $raw"
		    unless ($value =~ m{^/});
		$current->{KEY_COPY} = $value;
	    }
	    else {
		die "\"peer:\" must be yes or no, line $line_no. $config_file\nLine: $raw"
		    unless ($value eq 'yes' || $value eq 'no');
		$current->{PEER} = ($value eq 'yes');
	    }
	}
	else {
	    die "Invalid field \"$field\", line $line_no. $config_file\nLine: $raw";
	}
    }
    close ($fh);

    die "No \"spec-root:\" in $config_file\n" unless (defined ($cf{SPEC_ROOT}));
    die "No \"host:\" in $config_file\n" unless (@{$cf{HOSTS}});
    foreach my $host (@{$cf{HOSTS}}) {
	die "Host $host->{NAME} has \"key-copy:\" but no \"key:\". $config_file\n"
	    if (defined ($host->{KEY_COPY}) && !defined ($host->{KEY}));
    }
    $cf{MAX_AGE} //= DEFAULT_MAX_AGE;
    $cf{ATTRIBUTES} //= [split (/,/, DEFAULT_ATTRIBUTES)];
    $cf{SNAPSHOT_SUBDIR} //= DEFAULT_SNAPSHOT_SUBDIR;
    die "\"previous-snapshot:\" and \"previous-age:\" cannot both be used. $config_file\n"
	if (defined ($cf{PREVIOUS}) && defined ($cf{PREVIOUS_AGE}));
    $cf{CURRENT} //= DEFAULT_CURRENT;
    $cf{PREVIOUS} //= DEFAULT_PREVIOUS unless (defined ($cf{PREVIOUS_AGE}));
    if ((grep { $_->{PEER} } @{$cf{HOSTS}}) && !@{$cf{COMMON}}) {
	die "Peers are marked but there is no \"common:\" path. $config_file\n";
    }
    $cf{SYSTEM_ROOT} //= '/';
    $cf{CHROOTS} //= [];
    $cf{REFERENCE} //= [];
    if (@{$cf{REFERENCE}}) {
	$cf{REFERENCE_HOSTS} //= [ map { $_->{NAME} } @{$cf{HOSTS}} ];
	foreach my $name (@{$cf{REFERENCE_HOSTS}}) {
	    die "\"reference-hosts:\" names \"" . _esc ($name) . "\", which has no \"host:\" line. $config_file\n"
		unless (grep { $_->{NAME} eq $name } @{$cf{HOSTS}});
	}
    }
    else {
	die "\"reference-hosts:\" without \"reference:\". $config_file\n" if ($cf{REFERENCE_HOSTS});
	$cf{REFERENCE_HOSTS} = [];
    }
    foreach my $chroot (@{$cf{CHROOTS}}) {
	die "\"chroot: $chroot->{ROOT}\" has no \"chroot-hosts:\". $config_file\n"
	    unless (@{$chroot->{HOSTS}});
	foreach my $name (@{$chroot->{HOSTS}}) {
	    die "\"chroot-hosts:\" for $chroot->{ROOT} names \"" . _esc ($name) .
		"\", which has no \"host:\" line. $config_file\n"
		unless (grep { $_->{NAME} eq $name } @{$cf{HOSTS}});
	}
    }
    return \%cf;
}

# A common/except path: * and ? match within one path component; the
# pattern matches the path itself or anything beneath it.
sub _glob_to_regex {
    my ($glob) = @_;
    my $re = join ('', map { $_ eq '*' ? '[^/]*' : $_ eq '?' ? '[^/]' : quotemeta ($_) }
		   split (/([*?])/, $glob));
    return ($glob eq '/') ? qr{^/} : qr{^$re(?:/|\z)};
}

sub _when {
    my ($time) = @_;
    return POSIX::strftime ('%Y-%m-%d %H:%M', localtime ($time));
}

# 1. The changed file: missing, or older than max-age.
sub _check_changed_file {
    my ($cf, $host) = @_;
    my $path = "$cf->{SPEC_ROOT}/specs/$host->{NAME}.changed";
    my @stat = lstat ($path);

    if (!@stat) {
	return ("no changed file ($path): no record of a recent check (normal on the day after an update)");
    }
    my $age = (time () - $stat[9]) / 3600;
    if ($age > $cf->{MAX_AGE}) {
	return (sprintf ("changed file last written %s, %.0f hours ago (max-age %d)",
			 _when ($stat[9]), $age, $cf->{MAX_AGE}));
    }
    return ();
}

# Snapshot directories under the snapshot root, with their times (the
# directories' mtimes), newest first.
sub _list_snapshots {
    my ($cf) = @_;
    my @snapshots;

    return [] unless (defined ($cf->{SNAPSHOT_ROOT}));
    opendir (my $dh, $cf->{SNAPSHOT_ROOT}) ||
	die "Cannot read snapshot root $cf->{SNAPSHOT_ROOT}: $!\n";
    foreach my $name (readdir ($dh)) {
	next unless ($name =~ /^[\w-]+\.\d+\z/);
	my @stat = stat ("$cf->{SNAPSHOT_ROOT}/$name");
	next unless (@stat && S_ISDIR ($stat[2]));
	push (@snapshots, { NAME => $name, TIME => $stat[9] });
    }
    closedir ($dh);
    return [ sort { $b->{TIME} <=> $a->{TIME} } @snapshots ];
}

# The spec files of a host in one copy of its sigtree directory: the
# spec-of-specs and each tree spec, by name (signatures and changed files
# are not specs). Returns name => [path, size, dev, ino].
sub _spec_files {
    my ($sigtree_dir, $host) = @_;
    my %files;
    my $specs = "$sigtree_dir/specs";

    my @stat = lstat ("$specs/$host.spec");
    $files{"$host.spec"} = ["$specs/$host.spec", @stat[7, 0, 1]] if (@stat && S_ISREG ($stat[2]));
    if (opendir (my $dh, "$specs/$host")) {
	foreach my $name (readdir ($dh)) {
	    next if ($name eq '.' || $name eq '..' || $name =~ /\.sig\z/);
	    my $path = "$specs/$host/$name";
	    @stat = lstat ($path);
	    next unless (@stat && S_ISREG ($stat[2]));
	    $files{"$host/$name"} = [$path, @stat[7, 0, 1]];
	}
	closedir ($dh);
    }
    return \%files;
}

# SHA-256 of a file, cached by device and inode: rsnapshot hard-links a
# file that has not changed, so each version is read once.
sub _file_hash {
    my ($file, $cache) = @_;
    my ($path, $size, $dev, $ino) = @{$file};
    my $key = "$dev:$ino";

    return $cache->{$key} if (exists ($cache->{$key}));
    my $digest;
    if (sysopen (my $fh, $path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)) {
	binmode ($fh);
	my $sha = Digest::SHA->new (256);
	eval { $sha->addfile ($fh); $digest = $sha->hexdigest; 1 } or
	    warn "Could not read $path: $@";
	close ($fh);
    }
    else {
	warn "Could not open $path: $!\n";
    }
    $cache->{$key} = $digest;
    return $digest;
}

sub _same_file {
    my ($x, $y, $cache) = @_;
    return 0 unless ($x->[1] == $y->[1]);                       # size
    return 1 if ($x->[2] == $y->[2] && $x->[3] == $y->[3]);    # same inode
    my ($ha, $hb) = (_file_hash ($x, $cache), _file_hash ($y, $cache));
    return (defined ($ha) && defined ($hb) && $ha eq $hb);
}

# The current and previous snapshots, and every snapshot by time: the
# window (previous to current, oldest first) and the history before it.
# previous-age picks the newest snapshot at least that many days older
# than the current one. Returns (current, previous, window, history) or
# an error message.
sub _select_window {
    my ($cf, $snapshots) = @_;
    my %snap = map { $_->{NAME} => $_ } @{$snapshots};

    my $cur = $snap{$cf->{CURRENT}} or
	return ("snapshot $cf->{CURRENT} not found under $cf->{SNAPSHOT_ROOT}");
    my $prev;
    if (defined ($cf->{PREVIOUS_AGE})) {
	my $limit = $cur->{TIME} - $cf->{PREVIOUS_AGE} * DAY;
	($prev) = grep { $_->{TIME} <= $limit } @{$snapshots};     # newest first
	return ("no snapshot is $cf->{PREVIOUS_AGE} days older than $cur->{NAME}") unless ($prev);
    }
    else {
	$prev = $snap{$cf->{PREVIOUS}} or
	    return ("snapshot $cf->{PREVIOUS} not found under $cf->{SNAPSHOT_ROOT}");
    }
    return ("snapshot $prev->{NAME} is not older than $cur->{NAME}")
	unless ($prev->{TIME} < $cur->{TIME});
    my @by_time = reverse @{$snapshots};                           # oldest first
    my @window = grep { $_->{TIME} >= $prev->{TIME} && $_->{TIME} <= $cur->{TIME} } @by_time;
    my @history = grep { $_->{TIME} < $prev->{TIME} } @by_time;
    return (undef, $cur, $prev, \@window, \@history);
}

sub _snapshot_dir {
    my ($cf, $snap, $host) = @_;
    return "$cf->{SNAPSHOT_ROOT}/$snap->{NAME}/$host/$cf->{SNAPSHOT_SUBDIR}";
}

# 2 and 3. Spec files changed between the previous and current
# snapshots; and any spec that, anywhere in the window, goes back to a
# version it had before (an older signed spec put back). Specs record
# mtimes and ctimes, so an update cannot legitimately recreate an earlier
# copy. Walking every snapshot in the window, not just its two ends,
# catches a spec put back to the version that was current before the
# latest update, which the two ends would show as unchanged.
sub _check_snapshots {
    my ($cf, $host, $snapshots, $cache) = @_;
    my (@lines, %files);

    my ($error, $cur, $prev, $window, $history) = _select_window ($cf, $snapshots);
    return ($error) if (defined ($error));
    my $cur_dir = _snapshot_dir ($cf, $cur, $host->{NAME});
    unless (-d "$cur_dir/specs") {
	return ("no sigtree specs in snapshot $cur->{NAME} ($cur_dir/specs)");
    }
    foreach my $snap (@{$history}, @{$window}) {
	$files{$snap->{NAME}} = _spec_files (_snapshot_dir ($cf, $snap, $host->{NAME}), $host->{NAME});
    }
    my ($cur_files, $prev_files) = ($files{$cur->{NAME}}, $files{$prev->{NAME}});

    my (@changed, @added, @removed, @rolled_back);
    foreach my $name (sort keys %{$cur_files}) {
	if (!$prev_files->{$name}) {
	    push (@added, _esc ($name));
	}
	elsif (!_same_file ($cur_files->{$name}, $prev_files->{$name}, $cache)) {
	    push (@changed, _esc ($name));
	}
    }
    @removed = map { _esc ($_) } grep { !$cur_files->{$_} } sort keys %{$prev_files};

    my %in_window = map { $_->{NAME} => 1 } @{$window};
    my %names;
    foreach my $snap (@{$window}) {
	$names{$_} = 1 foreach (keys %{$files{$snap->{NAME}}});
    }
    foreach my $name (sort keys %names) {
	my (@versions, $current);   # versions: [file, snapshot] seen so far
	foreach my $snap (@{$history}, @{$window}) {
	    my $file = $files{$snap->{NAME}}{$name} or next;
	    next if ($current && _same_file ($file, $current->[0], $cache));
	    my ($earlier) = grep { (!$current || $_ != $current) && _same_file ($file, $_->[0], $cache) } @versions;
	    if ($earlier && $in_window{$snap->{NAME}} && $snap != $prev) {
		push (@rolled_back, _esc ($name) . " in $snap->{NAME} (" . _when ($snap->{TIME}) .
		      ") is identical to the copy in $earlier->[1]{NAME} (" . _when ($earlier->[1]{TIME}) .
		      "), after a different version in $current->[1]{NAME}: an older spec has been put back");
	    }
	    if ($earlier) {
		$current = $earlier;
	    }
	    else {
		$current = [$file, $snap];
		push (@versions, $current);
	    }
	}
    }

    my $span = "between $prev->{NAME} (" . _when ($prev->{TIME}) . ") and $cur->{NAME} (" .
	_when ($cur->{TIME}) . ")";
    push (@lines, _limited ("spec changed $span", \@changed)) if (@changed);
    push (@lines, _limited ("spec added $span", \@added)) if (@added);
    push (@lines, _limited ("spec removed $span", \@removed)) if (@removed);
    push (@lines, @rolled_back);
    return @lines;
}

# "label: a, b, c" with at most LIST_LIMIT names.
sub _limited {
    my ($label, $names) = @_;
    my @shown = @{$names}[0 .. ($#{$names} < LIST_LIMIT - 1 ? $#{$names} : LIST_LIMIT - 1)];
    my $more = @{$names} - @shown;
    return ("$label: " . join (', ', @shown) . ($more ? ", and $more more" : ''));
}

# 4. Signatures on the spec-of-specs and every tree spec in the spec
# root's copy, with the key pinned in the config. Each spec and its
# signature are copied into the private temp dir and the copy verified,
# so what is verified is what is later loaded. Returns the problem lines,
# the verified tree specs as [name, data], and whether every spec and the
# spec-of-specs verified.
sub _check_signatures {
    my ($cf, $host, $temp_dir) = @_;
    my (@lines, @specs);
    my $name = $host->{NAME};
    my $all_good = 1;

    my $key_file = _write_key ($host, $temp_dir);
    if (defined ($host->{KEY_COPY})) {
	if (open (my $cfh, '<', $host->{KEY_COPY})) {
	    my @key_lines = <$cfh>;
	    close ($cfh);
	    my $copy = $key_lines[1] // '';
	    chomp ($copy);
	    push (@lines, "key-copy $host->{KEY_COPY} does not match the key in the config")
		if ($copy ne $host->{KEY});
	}
	else {
	    push (@lines, "cannot read key-copy $host->{KEY_COPY}: $!");
	}
    }

    my $files = _spec_files ($cf->{SPEC_ROOT}, $name);
    unless ($files->{"$name.spec"}) {
	push (@lines, "no spec-of-specs $cf->{SPEC_ROOT}/specs/$name.spec");
	$all_good = 0;
    }
    foreach my $spec (sort keys %{$files}) {
	my ($data, $problem) = _verify_copy ($files->{$spec}[0], $temp_dir, $key_file);
	if (defined ($problem)) {
	    push (@lines, $problem);
	    $all_good = 0;
	}
	elsif ($spec ne "$name.spec") {
	    push (@specs, [$spec, $data]);
	}
    }
    return (\@lines, \@specs, $all_good);
}

# Write the host's pinned key as a signify public key file in the
# private temp dir, once, and return its path.
sub _write_key {
    my ($host, $temp_dir) = @_;
    my $key_file = "$temp_dir/$host->{NAME}.pub";

    return $key_file if (-e $key_file);
    sysopen (my $kfh, $key_file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600) ||
	die "Could not create $key_file: $!\n";
    print $kfh "untrusted comment: sigtree verify_hosts key for $host->{NAME}\n$host->{KEY}\n";
    close ($kfh) || die "Could not write $key_file: $!\n";
    return $key_file;
}

# Copy a spec and its .sig into the private temp dir and verify the copy,
# so what is verified is what is later loaded. Returns the data, or undef
# and a line saying what was wrong.
sub _verify_copy {
    my ($path, $temp_dir, $key_file) = @_;
    state $copy_count = 0;
    my $copy = "$temp_dir/spec." . ++$copy_count;
    my ($data, $problem);

    $data = _copy_file ($path, $copy);
    my $sig = _copy_file ("$path.sig", "$copy.sig");
    if (!defined ($data)) {
	$problem = "cannot read " . _esc ($path);
    }
    elsif (!defined ($sig)) {
	$problem = "no signature for " . _esc ($path);
    }
    elsif ($sig !~ /\Auntrusted comment: /) {
	# A GPG signature as sigtree writes one: the base64 lines of an
	# armored signature, ending in the "=" checksum line.
	my $gpg = ($sig =~ /\A-----BEGIN PGP SIGNATURE-----/ ||
		   $sig =~ m{\A[A-Za-z0-9+/=\s]+\n=[A-Za-z0-9+/]{4}\s*\z});
	$problem = "cannot verify " . _esc ($path) . ": its .sig is not a signify signature" .
	    ($gpg ? " but a GPG one (signed before this host moved to signify?)" : "");
    }
    elsif (!Signify::verify ($copy, { public_key_path => $key_file,
				      skip_signify_check => 1 })) {
	my @errors = Signify::signify_error ();
	my $reason = $errors[0] // 'unknown error';
	chomp ($reason);
	$problem = "BAD SIGNATURE on " . _esc ($path) . " (" . _esc ($reason) . ")";
    }
    unlink ($copy, "$copy.sig");
    return (defined ($problem) ? (undef, $problem) : ($data, undef));
}

# Copy a regular file (not through a symlink) and return its contents,
# or undef if it cannot be read.
sub _copy_file {
    my ($from, $to) = @_;
    my $data;

    sysopen (my $in, $from, O_RDONLY | O_NOFOLLOW | O_NONBLOCK) || return undef;
    my @stat = stat ($in);
    unless (@stat && S_ISREG ($stat[2])) {
	close ($in);
	return undef;
    }
    binmode ($in);
    local $/;
    $data = <$in>;
    close ($in);
    return undef unless (defined ($data));
    sysopen (my $out, $to, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600) ||
	die "Could not create $to: $!\n";
    binmode ($out);
    print $out $data;
    close ($out) || die "Could not write $to: $!\n";
    return $data;
}

# 5. Compare the peers' verified specs, in a child running as _sigtree.
sub _compare_peers {
    my ($cf, $verified, $uid, $gid, $osname) = @_;

    return () if (keys (%{$verified}) < 2);
    return _in_child ($uid, $gid, $osname, sub { _compare_specs ($cf, $verified) });
}

# Run $code in a child that has dropped to _sigtree and, on OpenBSD,
# pledged only stdio, and return the lines it returns, through a pipe.
# Specs are loaded only in such a child.
sub _in_child {
    my ($uid, $gid, $osname, $code) = @_;

    pipe (my $reader, my $writer) || die "pipe failed: $!\n";
    my $pid = fork ();
    die "fork failed: $!\n" unless (defined ($pid));
    if ($pid == 0) {
	close ($reader);
	my $text = eval {
	    POSIX::setgid ($gid) || die "setgid: $!\n";
	    $) = "$gid $gid";
	    POSIX::setuid ($uid) || die "setuid: $!\n";
	    die "could not drop privileges\n" if ($< != $uid || $> != $uid || $( != $gid);
	    if ($osname eq 'openbsd') {
		main::pledge () || die "pledge: $!\n";
	    }
	    join ('', map { "$_\n" } $code->());
	};
	$text = "ERROR: " . _esc ($@) . "\n" unless (defined ($text));
	while (length ($text)) {
	    my $written = syswrite ($writer, $text);
	    last unless ($written);
	    substr ($text, 0, $written) = '';
	}
	POSIX::_exit (0);
    }
    close ($writer);
    my @lines = <$reader>;
    close ($reader);
    waitpid ($pid, 0);
    my $status = $?;
    chomp (@lines);
    push (@lines, "ERROR: the process loading specs ended with status $status") if ($status != 0);
    return @lines;
}

sub _in_scope {
    my ($cf, $path) = @_;
    return 0 unless (grep { $path =~ $_->[1] } @{$cf->{COMMON}});
    return 0 if (grep { $path =~ $_->[1] } @{$cf->{EXCEPT}});
    return 1;
}

sub _compare_specs {
    my ($cf, $verified) = @_;
    my (%entries, %trees, @lines);
    my @attrs = @{$cf->{ATTRIBUTES}};

    foreach my $host (sort keys %{$verified}) {
	foreach my $spec (@{$verified->{$host}}) {
	    my ($name, $data) = @{$spec};
	    my $obj = _load_spec ($data, $name);
	    if (!$obj) {
		push (@lines, "$host: " . ($LOAD_PROBLEM // "cannot load spec " . _esc ($name)));
		next;
	    }
	    my $tree = $obj->{TREE};
	    push (@{$trees{$host}}, $tree);
	    foreach my $key (keys %{$obj->{FILEATTR}}) {
		my $full = ($key eq $tree) ? $tree : ($tree eq '/' ? "/$key" : "$tree/$key");
		next unless (_in_scope ($cf, $full));
		my $fa = $obj->{FILEATTR}{$key};
		next unless (ref ($fa));
		$entries{$full}{$host} = [ map { $fa->{$ATTR_FIELD{$_}} } @attrs ];
	    }
	}
    }

    my $covers = sub {
	my ($host, $path) = @_;
	return scalar (grep { $_ eq '/' || $path eq $_ || index ($path, "$_/") == 0 }
		       @{$trees{$host} || []});
    };
    my @hosts = sort keys %{$verified};
    my (%differs, %missing, %only, @no_majority);
    foreach my $path (sort keys %entries) {
	my $have = $entries{$path};
	my @covering = grep { $covers->($_, $path) } @hosts;
	next if (@covering < 2);
	my @present = grep { $have->{$_} } @covering;
	my @absent = grep { !$have->{$_} } @covering;
	if (@present == 1 && @covering >= 3) {
	    push (@{$only{$present[0]}}, _esc ($path));
	    next;
	}
	if (@present * 2 > @covering) {
	    push (@{$missing{$_}}, _esc ($path)) foreach (@absent);
	}
	next if (@present < 2);
	my %count;
	my %value;
	foreach my $host (@present) {
	    $value{$host} = join ("\0", map { $_ // '-' } @{$have->{$host}});
	}
	$count{$value{$_}}++ foreach (@present);
	my ($top) = sort { $count{$b} <=> $count{$a} } keys %count;
	next if (keys (%count) == 1);
	if ($count{$top} * 2 <= @present) {
	    push (@no_majority, _esc ($path));
	    next;
	}
	my ($ref_host) = grep { $value{$_} eq $top } @present;
	foreach my $host (grep { $value{$_} ne $top } @present) {
	    my @which = grep { ($have->{$host}[$_] // '-') ne ($have->{$ref_host}[$_] // '-') } 0 .. $#attrs;
	    push (@{$differs{$host}}, _esc ($path) . " (" . join (',', @attrs[@which]) . ")");
	}
    }

    foreach my $host (@hosts) {
	push (@lines, _limited ("$host differs from the other peers", $differs{$host}))
	    if ($differs{$host});
	push (@lines, _limited ("$host lacks", $missing{$host})) if ($missing{$host});
	push (@lines, _limited ("only $host has", $only{$host})) if ($only{$host});
    }
    push (@lines, _limited ("no majority among the peers", \@no_majority))
	if (@no_majority);
    return @lines;
}

# The detail query, on demand: "verify_hosts <host>" shows what changed
# in each of the host's specs that differ between the previous and
# current snapshots; "verify_hosts <host> <spec>" does it for one spec;
# "verify_hosts <host> /path" for one file, and if the snapshots hold
# backups of both versions of it (found by their digests), shows a diff.
# Both versions of each spec are verified with the host's pinned key and
# loaded only as _sigtree.
sub _details {
    my ($cf, $verbose, $osname, $host_name, $target, @extra) = @_;

    die "Usage: sigtree.pl [-c config] verify_hosts [host [spec | /path]]\n" if (@extra);
    my ($host) = grep { $_->{NAME} eq $host_name } @{$cf->{HOSTS}};
    die "Host \"" . _esc ($host_name) . "\" is not in the config.\n" unless ($host);
    my $name = $host->{NAME};
    die "Host $name has no signify key in the config; specs are loaded only after their signatures verify.\n"
	unless (defined ($host->{KEY}));
    die "The detail query needs \"snapshot-root:\" in the config.\n"
	unless (defined ($cf->{SNAPSHOT_ROOT}));
    my $path_mode = (defined ($target) && $target =~ m{^/});
    if ($path_mode) {
	die "Invalid path \"" . _esc ($target) . "\".\n"
	    if ($target =~ m{(?:^|/)\.\.(?:/|\z)} || $target =~ /[\x00-\x1f\x7f]/ || $target eq '/');
	$target =~ s{/+\z}{};
    }
    elsif (defined ($target)) {
	die "Invalid spec name \"" . _esc ($target) . "\".\n"
	    unless ($target =~ m{^(?:[\w-][\w.-]*/)?[\w-][\w.-]*\z});
    }
    _require_signify ();
    my ($uid, $gid) = ((getpwnam ('_sigtree'))[2], (getgrnam ('_sigtree'))[2]);
    die "The detail query needs the _sigtree user and group.\n"
	unless (defined ($uid) && defined ($gid));
    die "The detail query must be run as root.\n" if ($> != 0);
    _restrict ($cf, $osname, $path_mode);

    my $temp_dir = main::mkdtemp ('/tmp/sigtree.XXXXXXXX') or
	die "Could not create a temp dir: $!\n";
    my @out;
    my $ok = eval {
	my $snapshots = _list_snapshots ($cf);
	my ($error, $cur, $prev, $window) = _select_window ($cf, $snapshots);
	die "$error\n" if (defined ($error));
	my %cache;
	# The snapshots strictly between the two ends, oldest first: if the
	# previous copy of a spec cannot be verified (a GPG signature from
	# before the host moved to signify, say), the oldest of these whose
	# copy does verify becomes that spec's old end.
	my @later = grep { $_->{TIME} > $prev->{TIME} && $_->{TIME} < $cur->{TIME} } @{$window};
	my %later_files;
	my $cur_files = _spec_files (_snapshot_dir ($cf, $cur, $name), $name);
	my $prev_files = _spec_files (_snapshot_dir ($cf, $prev, $name), $name);

	my @names;
	if ($path_mode) {
	    # Every tree spec whose tree could hold the path.
	    my $dir = $target;
	    while ($dir ne '/' && $dir ne '.' && $dir ne '') {
		my $spec = "$name/" . main::path_to_spec ($dir);
		push (@names, $spec) if ($cur_files->{$spec} || $prev_files->{$spec});
		$dir = File::Basename::dirname ($dir);
	    }
	    die "No spec of $name in $cur->{NAME} or $prev->{NAME} covers " . _esc ($target) . ".\n"
		unless (@names);
	}
	elsif (defined ($target)) {
	    my $spec = ($cur_files->{$target} || $prev_files->{$target}) ? $target : "$name/$target";
	    die "No spec \"" . _esc ($target) . "\" for $name in $cur->{NAME} or $prev->{NAME}.\n"
		unless ($cur_files->{$spec} || $prev_files->{$spec});
	    @names = ($spec);
	}
	else {
	    my %all = (%{$cur_files}, %{$prev_files});
	    @names = grep { !$cur_files->{$_} || !$prev_files->{$_} ||
			    !_same_file ($cur_files->{$_}, $prev_files->{$_}, \%cache) } sort keys %all;
	}

	my $key_file = _write_key ($host, $temp_dir);
	# A spec is shown only if every version of it present verifies; the
	# others are listed with the reason, and the rest are still shown.
	my (@pairs, @problems);
	foreach my $spec (@names) {
	    my (@spec_problems, $old_data, $new_data);
	    if ($cur_files->{$spec}) {
		($new_data, my $problem) = _verify_copy ($cur_files->{$spec}[0], $temp_dir, $key_file);
		push (@spec_problems, $problem) if (defined ($problem));
	    }
	    if ($prev_files->{$spec}) {
		($old_data, my $problem) = _verify_copy ($prev_files->{$spec}[0], $temp_dir, $key_file);
		if (defined ($problem) && !@spec_problems) {
		    my $from;
		    foreach my $snap (@later) {
			$later_files{$snap->{NAME}} //=
			    _spec_files (_snapshot_dir ($cf, $snap, $name), $name);
			my $file = $later_files{$snap->{NAME}}{$spec} or next;
			my ($data, $later_problem) = _verify_copy ($file->[0], $temp_dir, $key_file);
			next if (defined ($later_problem));
			($old_data, $from) = ($data, $snap);
			last;
		    }
		    if ($from) {
			push (@problems, $problem, "   so changes in " . _esc ($spec) . " are shown from " .
			      "$from->{NAME} (" . _when ($from->{TIME}) . "), the oldest copy in the window that verifies");
		    }
		    else {
			push (@spec_problems, $problem);
		    }
		}
		elsif (defined ($problem)) {
		    push (@spec_problems, $problem);
		}
	    }
	    if (@spec_problems) {
		push (@problems, @spec_problems, "   so changes in " . _esc ($spec) . " are not shown");
	    }
	    else {
		push (@pairs, [$spec, $old_data, $new_data]);
	    }
	}

	push (@out, "$name: $prev->{NAME} (" . _when ($prev->{TIME}) . ") to $cur->{NAME} (" .
	      _when ($cur->{TIME}) . ")");
	push (@out, map { "   $_" } @problems);
	if (!@pairs && !@problems) {
	    push (@out, "   no spec changed");
	}
	my @lines = @pairs ? _in_child ($uid, $gid, $osname,
					sub { _spec_details (\@pairs, $path_mode ? $target : undef) }) : ();
	my $digests;
	if ($path_mode && @lines && $lines[0] =~ /^\x01/) {
	    $digests = shift (@lines);
	}
	push (@out, map { "   $_" } @lines);
	push (@out, _backup_diff ($cf, $name, $target, $digests, $snapshots, \%cache))
	    if ($path_mode && defined ($digests));
	push (@out, _reference_diff ($cf, $name, $target, $digests, $snapshots, \%cache))
	    if ($path_mode && grep { $_ eq $target } @{$cf->{REFERENCE}});
	1;
    };
    my $error = $@;
    _remove_dir ($temp_dir);
    die $error unless ($ok);
    print "$_\n" foreach (@out);
    return 0;
}

# FileAttr fields shown by the detail query, in order.
# The attributes the detail query shows (AttrDisplay's filter). A spec
# records type, mode, owner, group, size, link count and times for every
# path, whatever its set's keywords, so a change in an attribute the host
# never checks (most often mtime and ctime) would otherwise be listed
# too. By default every attribute but mtime and ctime is shown; -v shows
# them as well; -k names the ones to show, as sigtree keywords. The
# host's own config is not read: it is unsigned and written by the host.
our $TIMES_HINT;
sub _set_show_fields {
    my ($verbose, $keywords) = @_;
    $TIMES_HINT = !defined ($keywords) && !$verbose;
    if (defined ($keywords)) {
	AttrDisplay::set_filter (AttrDisplay::keyword_attrs ($keywords));
    }
    elsif (!$verbose) {
	AttrDisplay::set_filter (grep { $_ ne 'mtime' && $_ ne 'ctime' } AttrDisplay::attrs ());
    }
}

# The FileAttr entries of a loaded spec, by full path.
sub _entries {
    my ($obj) = @_;
    my %entries;
    my $tree = $obj->{TREE};
    foreach my $key (keys %{$obj->{FILEATTR}}) {
	my $full = ($key eq $tree) ? $tree : ($tree eq '/' ? "/$key" : "$tree/$key");
	$entries{$full} = $obj->{FILEATTR}{$key} if (ref ($obj->{FILEATTR}{$key}));
    }
    return \%entries;
}

# Load a verified spec. Given its name (<host>.spec or <host>/<spec>),
# also check that it holds the tree its file name is for (1.32): a
# validly signed spec copied over another tree's spec would otherwise be
# taken for that tree, and the tree whose name it took would drop out of
# every comparison. On a mismatch it returns undef and says why in
# $LOAD_PROBLEM (declared at the top of the package).
sub _load_spec {
    my ($data, $name) = @_;
    $LOAD_PROBLEM = undef;
    return undef unless (defined ($data));
    open (my $mem, '<', \$data) || return undef;
    my $obj = eval { fd_retrieve ($mem) };
    close ($mem);
    return undef unless (ref ($obj) && defined ($obj->{TREE}) && ref ($obj->{FILEATTR}) eq 'HASH');
    if (defined ($name) && !_name_fits_tree ($name, $obj->{TREE})) {
	$LOAD_PROBLEM = "spec " . _esc ($name) . " holds tree " . _esc ($obj->{TREE}) .
	    ", not the tree its name is for (a spec copied over another's?)";
	return undef;
    }
    return $obj;
}

# A tree spec is named for its tree (path_to_spec), and a host's spec of
# specs (<host>.spec) holds its spec directory, specs/<host>.
sub _name_fits_tree {
    my ($name, $tree) = @_;
    return (File::Basename::basename ($tree) eq $1) if ($name =~ m{\A([^/]+)\.spec\z});
    return (main::path_to_spec ($tree) eq $1) if ($name =~ m{/([^/]+)\z});
    return 0;
}

# Runs in the _sigtree child. For a path, the first line returned is
# "\x01" followed by the old and new digests and sizes ("-" if none).
sub _spec_details {
    my ($pairs, $path) = @_;
    my (@lines, %bad);

    # A copy holding another tree than its name says is reported, and that
    # spec is left out.
    foreach my $pair (@{$pairs}) {
	foreach my $i (1, 2) {
	    next if (!defined ($pair->[$i]) || _load_spec ($pair->[$i], $pair->[0]) ||
		     !defined ($LOAD_PROBLEM));
	    push (@lines, (($i == 1) ? "previous" : "current") . " copy of $LOAD_PROBLEM");
	    $bad{$pair->[0]} = 1;
	}
    }
    $pairs = [ grep { !$bad{$_->[0]} } @{$pairs} ];

    if (defined ($path)) {
	# The longest tree that holds the path.
	my ($best, $best_tree);
	foreach my $pair (@{$pairs}) {
	    foreach my $obj (map { _load_spec ($_) } @{$pair}[1, 2]) {
		next unless ($obj);
		my $tree = $obj->{TREE};
		next unless ($path eq $tree || index ($path, "$tree/") == 0);
		($best, $best_tree) = ($pair, $tree) if (!defined ($best_tree) || length ($tree) > length ($best_tree));
	    }
	}
	return (@lines, "no spec holds " . _esc ($path)) unless ($best);
	my ($spec, $old_data, $new_data) = @{$best};
	my ($old, $new) = map { my $o = _load_spec ($_); $o ? _entries ($o)->{$path} : undef }
	    ($old_data, $new_data);
	my $tok = sub { my ($fa, $field) = @_;
			my $v = $fa ? $fa->{$field} : undef;
			return (defined ($v) && $v =~ /^[0-9a-f]+\z/i) ? lc ($v) : '-' };
	my $size = sub { my ($fa) = @_;
			 return ($fa && defined ($fa->{SIZE}) && $fa->{SIZE} =~ /^\d+\z/) ? $fa->{SIZE} : '-' };
	push (@lines, "\x01" . join (' ', $tok->($old, 'SHADIGEST'), $tok->($new, 'SHADIGEST'),
				     $size->($old), $size->($new)));
	push (@lines, _esc ($path) . " (in spec " . _esc ($spec) . "):");
	if (!$old && !$new) {
	    push (@lines, "   not in either version of the spec");
	}
	elsif (!$old) {
	    push (@lines, "   added: " . _attr_summary ($new));
	}
	elsif (!$new) {
	    push (@lines, "   removed (was " . _attr_summary ($old) . ")");
	}
	else {
	    my @diffs = _attr_changes ($old, $new);
	    my @all = _attr_changes ($old, $new, 1);
	    push (@lines, @diffs ? map { "   $_" } @diffs :
		  @all ? "   changed only in attributes not shown (" .
		  join (', ', map { (split (/ /, $_))[0] } @all) . ")" : "   unchanged");
	}
	return @lines;
    }

    foreach my $pair (@{$pairs}) {
	my ($spec, $old_data, $new_data) = @{$pair};
	my ($old, $new) = map { _load_spec ($_) } ($old_data, $new_data);
	if (!$old && !$new) {
	    push (@lines, _esc ($spec) . ": cannot load either version");
	    next;
	}
	if (!$old || !$new) {
	    push (@lines, _esc ($spec) . ": " . ($old ? "removed" : "added") . " (tree " .
		  _esc (($old || $new)->{TREE}) . ")");
	    next;
	}
	my ($oe, $ne) = (_entries ($old), _entries ($new));
	my @changes;
	my $hidden = 0;
	my %all = (%{$oe}, %{$ne});
	foreach my $path (sort keys %all) {
	    if (!$oe->{$path}) {
		push (@changes, "   added " . _esc ($path) . ": " . _attr_summary ($ne->{$path}));
	    }
	    elsif (!$ne->{$path}) {
		push (@changes, "   removed " . _esc ($path));
	    }
	    else {
		my @diffs = _attr_changes ($oe->{$path}, $ne->{$path});
		if (@diffs) {
		    push (@changes, "   changed " . _esc ($path) . ": " . join ('; ', @diffs));
		}
		elsif (_attr_changes ($oe->{$path}, $ne->{$path}, 1)) {
		    $hidden++;
		}
	    }
	}
	push (@lines, _esc ($spec) . " (tree " . _esc ($new->{TREE}) . "): " .
	      (@changes ? scalar (@changes) . " paths" : "no paths changed") .
	      ($hidden ? ", and $hidden changed only in attributes not shown" .
	       ($TIMES_HINT ? ' (-v shows mtime and ctime)' : '') : ''),
	      @changes);
    }
    return @lines;
}

sub _attr_summary {
    my ($fa) = @_;
    return join (', ', map { "$_ " . AttrDisplay::value ($_, $fa->{uc ($_)}) }
		 grep { defined ($fa->{uc ($_)}) } qw(type mode uid gid size));
}

# The changes between two versions of a path's record, as AttrDisplay
# shows them (device numbers raw: the spec may be from another OS), for
# the attributes shown, or for all with $all_fields.
sub _attr_changes {
    my ($old, $new, $all_fields) = @_;
    my @diffs;
    foreach my $attr (grep { $_ ne 'mtimestasis' } AttrDisplay::attrs ()) {
	next unless ($all_fields || AttrDisplay::shown ($attr));
	my $field = AttrDisplay::field ($attr);
	my ($o, $n) = ($old->{$field}, $new->{$field});
	next if (!defined ($o) && !defined ($n));
	next if (defined ($o) && defined ($n) && $o eq $n);
	push (@diffs, AttrDisplay::change ($attr, $o, $n, 'raw_rdev' => 1));
    }
    return @diffs;
}

# Hash a backup copy with the digest the spec's hex length implies:
# SHA-3 first (sigtree's default), then SHA-2 of the same size. Returns
# true if either matches. Cached by inode and digest.
sub _backup_matches {
    my ($path, $digest, $cache) = @_;
    my %bits = (56 => 224, 64 => 256, 96 => 384, 128 => 512);
    my $bits = $bits{length ($digest)} or return 0;
    my @stat = lstat ($path);
    return 0 unless (@stat && S_ISREG ($stat[2]));
    foreach my $family ('sha3', 'sha2') {
	my $key = "$stat[0]:$stat[1]:$family-$bits";
	if (!exists ($cache->{$key})) {
	    $cache->{$key} = undef;
	    if (sysopen (my $fh, $path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)) {
		binmode ($fh);
		my $ctx = ($family eq 'sha3') ? Digest::SHA3->new ($bits) : Digest::SHA->new ($bits);
		eval { $ctx->addfile ($fh); $cache->{$key} = $ctx->hexdigest; 1 } or
		    warn "Could not read " . _esc ($path) . ": $@";
		close ($fh);
	    }
	}
	return 1 if (defined ($cache->{$key}) && $cache->{$key} eq $digest);
    }
    return 0;
}

# For the detail query on one file: find a backup copy of each version
# (by digest, size first) in the snapshots and show a diff of the two.
sub _backup_diff {
    my ($cf, $name, $path, $digests, $snapshots, $cache) = @_;
    my @lines;

    my ($old_digest, $new_digest, $old_size, $new_size) =
	($digests =~ /^\x01([0-9a-f]+|-) ([0-9a-f]+|-) (\d+|-) (\d+|-)\z/);
    return ("   (no digests to look for in the backups)") unless (defined ($new_size));
    return () if ($old_digest eq '-' && $new_digest eq '-');
    return ("   (the file's digest did not change)") if ($old_digest eq $new_digest);
    return ("   (only one version has a digest, so no diff)") if ($old_digest eq '-' || $new_digest eq '-');

    my %found;
    foreach my $snap (@{$snapshots}) {           # newest first
	my $copy = "$cf->{SNAPSHOT_ROOT}/$snap->{NAME}/$name$path";
	my @stat = lstat ($copy);
	next unless (@stat && S_ISREG ($stat[2]));
	foreach my $want (['old', $old_digest, $old_size], ['new', $new_digest, $new_size]) {
	    my ($which, $digest, $size) = @{$want};
	    next if ($found{$which});
	    next if ($size ne '-' && $stat[7] != $size);
	    $found{$which} = [$copy, $snap] if (_backup_matches ($copy, $digest, $cache));
	}
	last if ($found{old} && $found{new});
    }
    foreach my $which ('old', 'new') {
	push (@lines, "   no backup copy matches the $which version") unless ($found{$which});
    }
    return @lines if (@lines);

    my ($old_copy, $old_snap) = @{$found{old}};
    my ($new_copy, $new_snap) = @{$found{new}};
    push (@lines, "   backups: old version in $old_snap->{NAME}, new version in $new_snap->{NAME}");
    push (@lines, _diff_files ($old_copy, "$old_snap->{NAME}:$path", $new_copy, "$new_snap->{NAME}:$path"));
    return @lines;
}

# diff -u of two files, escaped; for a binary file, just the sizes.
sub _diff_files {
    my ($x, $xlabel, $y, $ylabel) = @_;
    my @lines;

    foreach my $file ($x, $y) {
	if (open (my $fh, '<', $file)) {
	    binmode ($fh);
	    my $head = '';
	    read ($fh, $head, 8192);
	    close ($fh);
	    if (index ($head, "\0") >= 0) {
		return ("   binary file: sizes " . (-s $x) . " and " . (-s $y));
	    }
	}
    }
    open (my $dfh, '-|', DIFF, '-u', '-L', $xlabel, '-L', $ylabel, $x, $y) ||
	return ("   could not run " . DIFF . ": $!");
    while (my $line = <$dfh>) {
	chomp ($line);
	push (@lines, '   ' . _esc_keep_tabs ($line));
    }
    close ($dfh);
    my $status = $?;
    push (@lines, "   " . DIFF . " failed (status $status)") if ($status >> 8 > 1 || ($status & 127));
    return @lines;
}

# For the detail query on a reference file: compare the host's current
# version (its digest in the current snapshot's spec) with the reference
# copy on this host, and if they differ, diff the backup copy of the
# host's version against it.
sub _reference_diff {
    my ($cf, $name, $path, $digests, $snapshots, $cache) = @_;

    return ("   reference copy: $name" . "'s specs do not record " . _esc ($path))
	unless (defined ($digests));
    my ($new_digest, $new_size) = ($digests =~ /^\x01(?:[0-9a-f]+|-) ([0-9a-f]+|-) (?:\d+|-) (\d+|-)\z/);
    return ("   reference copy: no digest recorded for $name" . "'s current version")
	if (!defined ($new_digest) || $new_digest eq '-');
    return ("   same as the reference copy") if (_backup_matches ($path, $new_digest, $cache));
    foreach my $snap (@{$snapshots}) {           # newest first
	my $copy = "$cf->{SNAPSHOT_ROOT}/$snap->{NAME}/$name$path";
	my @stat = lstat ($copy);
	next unless (@stat && S_ISREG ($stat[2]));
	next if ($new_size ne '-' && $stat[7] != $new_size);
	next unless (_backup_matches ($copy, $new_digest, $cache));
	return ("   differs from the reference copy (" . _esc ($path) . " here); $name" .
		"'s version is in $snap->{NAME}:",
		_diff_files ($copy, "$snap->{NAME}:$path", $path, "reference:$path"));
    }
    return ("   differs from the reference copy; no backup copy of $name" . "'s version to diff");
}

sub _esc_keep_tabs {
    my ($text) = @_;
    $text =~ s/([\x00-\x08\x0a-\x1f\x7f])/sprintf ('\\x%02x', ord ($1))/ge;
    return $text;
}

# 7. Reference files: files on this host (where verify_hosts runs) that
# every host in reference-hosts: (default all) must have, the same. The
# digests of this host's copies are taken first, in each form a spec may
# hold (SHA-3 or SHA-2, by size); each host's verified specs are then
# compared with them in the _sigtree child.
sub _reference_digests {
    my ($cf) = @_;
    my %digests;

    foreach my $path (@{$cf->{REFERENCE}}) {
	my @stat = lstat ($path);
	unless (@stat && S_ISREG ($stat[2])) {
	    $digests{$path} = undef;
	    next;
	}
	foreach my $bits (224, 256, 384, 512) {
	    foreach my $ctx (Digest::SHA3->new ($bits), Digest::SHA->new ($bits)) {
		sysopen (my $fh, $path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK) || next;
		binmode ($fh);
		eval { $ctx->addfile ($fh); $digests{$path}{$ctx->hexdigest} = 1; 1 };
		close ($fh);
	    }
	}
    }
    return \%digests;
}

sub _check_references {
    my ($cf, $verified, $digests) = @_;
    my (@lines, %lacks, %differs, %no_digest);

    foreach my $path (@{$cf->{REFERENCE}}) {
	push (@lines, "cannot read the reference copy " . _esc ($path) . " here")
	    unless ($digests->{$path});
    }
    foreach my $host (@{$cf->{REFERENCE_HOSTS}}) {
	next unless ($verified->{$host});
	my %entries;
	foreach my $spec (@{$verified->{$host}}) {
	    my $obj = _load_spec ($spec->[1], $spec->[0]);
	    if (!$obj) {
		push (@lines, "$host: $LOAD_PROBLEM") if (defined ($LOAD_PROBLEM));
		next;
	    }
	    my $e = _entries ($obj);
	    @entries{keys %{$e}} = values %{$e};
	}
	foreach my $path (@{$cf->{REFERENCE}}) {
	    next unless ($digests->{$path});
	    my $fa = $entries{$path};
	    if (!$fa || ($fa->{TYPE} // '') ne 'file') {
		push (@{$lacks{$host}}, _esc ($path));
	    }
	    elsif (!defined ($fa->{SHADIGEST}) || $fa->{SHADIGEST} !~ /^[0-9a-f]+\z/i) {
		push (@{$no_digest{$host}}, _esc ($path));
	    }
	    elsif (!$digests->{$path}{lc ($fa->{SHADIGEST})}) {
		push (@{$differs{$host}}, _esc ($path));
	    }
	}
    }
    foreach my $host (@{$cf->{REFERENCE_HOSTS}}) {
	push (@lines, _limited ("$host differs from the reference copy", $differs{$host})) if ($differs{$host});
	push (@lines, _limited ("$host lacks (not in its specs)", $lacks{$host})) if ($lacks{$host});
	push (@lines, _limited ("$host records no digest for", $no_digest{$host})) if ($no_digest{$host});
    }
    return @lines;
}

# 6. Chroots, from the verified specs of the hosts that have them, in the
# _sigtree child. For each host's copy of each chroot:
#   - no setuid or setgid file anywhere in it, and no device node outside
#     its dev/;
#   - in the mirrored directories, dev/ and etc/: everything owned by
#     root and not group or world writable (other areas, such as htdocs,
#     keep their own owners and are left to the ordinary checks);
#   - under each directory named in allow-only:, nothing that is not
#     listed;
#   - under each mirror: directory, each file the same (type, digest,
#     mode, owner, group, device number, link target) as the file at the
#     same path on the host's own system, and none without one unless
#     listed in allow-extra: (mirror-except: skips files that differ by
#     design, such as a wrapper installed in place of the system's copy;
#     a relinked system library that its chroot copy no longer matches is
#     reported, as a sign that the chroot needs rebuilding);
# and, across the hosts that have the chroot, files they all have in its
# system parts (mirrored directories, dev/, etc/) must match one another;
# compare-except: leaves out paths there that differ by design.
# rules-except: exempts paths from the first two.
# Device nodes are exempt from the writable rule (dev/null is mode 666).
sub _check_chroots {
    my ($cf, $verified) = @_;
    my (@lines, %entries);

    foreach my $host (sort keys %{$verified}) {
	foreach my $spec (@{$verified->{$host}}) {
	    my $obj = _load_spec ($spec->[1], $spec->[0]);
	    if (!$obj) {
		push (@lines, "$host: " . ($LOAD_PROBLEM // "cannot load spec " . _esc ($spec->[0])));
		next;
	    }
	    my $e = _entries ($obj);
	    @{$entries{$host}}{keys %{$e}} = values %{$e};
	}
    }
    my $sysroot = $cf->{SYSTEM_ROOT};
    my @categories = (['setuid or setgid', 'SETID'], ['device node outside dev/', 'DEVICE'],
		      ['not owned by root', 'OWNER'], ['group or world writable', 'WRITABLE'],
		      ['not in allow-only', 'NOT_ALLOWED'],
		      ['no copy on the system (not in allow-extra)', 'NO_COUNTERPART'],
		      ['differs from the system copy', 'DIFFERS']);

    foreach my $chroot (@{$cf->{CHROOTS}}) {
	my $root = $chroot->{ROOT};
	my @hosts = grep { $entries{$_} } @{$chroot->{HOSTS}};
	my %allow_dir = map { (my $d = $_->[0]) =~ s{/[^/]*\z}{}; ($_->[0] =~ m{/} ? $d : '') => 1 }
	    @{$chroot->{ALLOW_ONLY}};
	foreach my $host (@hosts) {
	    my $e = $entries{$host};
	    my @paths = sort grep { $_ eq $root || index ($_, "$root/") == 0 } keys %{$e};
	    if (!@paths) {
		push (@lines, "Chroot $root on $host:", "   not in $host" . "'s specs");
		next;
	    }
	    my %found;
	    foreach my $path (@paths) {
		my $fa = $e->{$path};
		my $rel = ($path eq $root) ? '' : substr ($path, length ($root) + 1);
		my $type = $fa->{TYPE} // '';
		my $mode = $fa->{MODE};
		my $under = sub { $rel eq $_[0] || index ($rel, "$_[0]/") == 0 };
		my $exempt = grep { $path =~ $_->[1] } @{$chroot->{RULES_EXCEPT}};
		my $shown = _esc ($rel eq '' ? '.' : $rel);
		if (!$exempt && $type eq 'file' && defined ($mode) && ($mode & 06000)) {
		    push (@{$found{SETID}}, $shown . sprintf (' (%o)', $mode & 07777));
		}
		if (!$exempt && $type =~ /device/ && !$under->('dev')) {
		    push (@{$found{DEVICE}}, $shown);
		}
		my $mirrored = grep { $under->($_) } @{$chroot->{MIRROR}};
		if (!$exempt && $type ne 'link' && ($mirrored || $under->('dev') || $under->('etc'))) {
		    push (@{$found{OWNER}}, "$shown (uid $fa->{UID})")
			if (defined ($fa->{UID}) && $fa->{UID} != 0);
		    # Device nodes such as dev/null are writable by design; their
		    # modes are checked against the system's by the mirror check.
		    push (@{$found{WRITABLE}}, $shown . sprintf (' (%o)', $mode & 07777))
			if ($type !~ /device/ && defined ($mode) && ($mode & 022));
		}
		foreach my $dir (keys %allow_dir) {
		    # '' is the chroot's top level: its direct entries only.
		    next unless ($dir eq '' ? ($rel ne '' && $rel !~ m{/}) : index ($rel, "$dir/") == 0);
		    push (@{$found{NOT_ALLOWED}}, $shown)
			unless (grep { $path =~ $_->[1] } @{$chroot->{ALLOW_ONLY}});
		}
		next unless ($mirrored);
		next if (grep { $path =~ $_->[1] } @{$chroot->{MIRROR_EXCEPT}});
		my $sys = ($sysroot eq '/') ? "/$rel" : "$sysroot/$rel";
		my $sfa = $e->{$sys};
		if (!$sfa) {
		    push (@{$found{NO_COUNTERPART}}, $shown)
			unless (grep { $path =~ $_->[1] } @{$chroot->{ALLOW_EXTRA}});
		    next;
		}
		my @diffs = _copy_diff ($fa, $root, $sfa, $sysroot);
		push (@{$found{DIFFERS}}, "$shown (" . join (',', @diffs) . ")") if (@diffs);
	    }
	    my @found = map { _limited ($_->[0], $found{$_->[1]}) } grep { $found{$_->[1]} } @categories;
	    push (@lines, "Chroot $root on $host:", map { "   $_" } @found) if (@found);
	}

	# Files that every host's copy of the chroot has must be the same,
	# in the system parts only (the mirrored directories, dev/ and
	# etc/): the rest (htdocs, cgi-bin, logs) serves each host's own
	# purpose. compare-except: leaves out paths that differ by design, and
	# so does except: through each path's system counterpart (1.32c): a
	# chroot's libc or ld.so is a copy of its own host's relinked system
	# file, so the hosts' copies must differ. The mirror check above still
	# compares each copy with its own host's system file.
	next if (@hosts < 2);
	my ($first, @rest) = @hosts;
	my @diffs;
	foreach my $path (sort grep { index ($_, "$root/") == 0 } keys %{$entries{$first}}) {
	    next if (grep { !$entries{$_}{$path} } @rest);
	    my $rel = substr ($path, length ($root) + 1);
	    next unless (grep { $rel eq $_ || index ($rel, "$_/") == 0 } (@{$chroot->{MIRROR}}, 'dev', 'etc'));
	    next if (grep { $path =~ $_->[1] } @{$chroot->{COMPARE_EXCEPT}});
	    my $system_path = ($sysroot eq '/') ? "/$rel" : "$sysroot/$rel";
	    next if (grep { $system_path =~ $_->[1] } @{$cf->{EXCEPT}});
	    foreach my $other (@rest) {
		my @d = _copy_diff ($entries{$first}{$path}, $root, $entries{$other}{$path}, $root);
		push (@diffs, _esc ($rel) . " ($first and $other: " . join (',', @d) . ")") if (@d);
	    }
	}
	push (@lines, "Chroot $root across " . join (', ', @hosts) . ":",
	      "   " . _limited ('differs between the hosts', \@diffs)) if (@diffs);
    }
    return @lines;
}

# The attributes in which two copies of a file differ: for directories
# their type, mode and owner; for anything else also digest, device
# number and link target, with link targets read relative to each copy's
# root (a link in a chroot points into the chroot).
sub _copy_diff {
    my ($x, $xroot, $y, $yroot) = @_;
    my @fields = (($x->{TYPE} // '') eq 'dir' && ($y->{TYPE} // '') eq 'dir') ?
	qw(TYPE MODE UID GID) : qw(TYPE SHADIGEST MODE UID GID RDEV LINK);
    my $rel_link = sub {
	my ($link, $root) = @_;
	return $link if (!defined ($link) || $root eq '/');
	return '/' if ($link eq $root);
	return (index ($link, "$root/") == 0) ? substr ($link, length ($root)) : $link;
    };
    my @diffs;
    foreach my $field (@fields) {
	my ($a1, $b1) = ($x->{$field}, $y->{$field});
	($a1, $b1) = ($rel_link->($a1, $xroot), $rel_link->($b1, $yroot)) if ($field eq 'LINK');
	next if (!defined ($a1) && !defined ($b1));
	next if (defined ($a1) && defined ($b1) && $a1 eq $b1);
	push (@diffs, lc ($field));
    }
    return @diffs;
}

# Remove the private temp dir and the plain files in it.
sub _remove_dir {
    my ($dir) = @_;
    if (opendir (my $dh, $dir)) {
	foreach my $name (readdir ($dh)) {
	    next if ($name eq '.' || $name eq '..');
	    unlink ("$dir/$name") if ($name =~ /^([\w.-]+)\z/);
	}
	closedir ($dh);
    }
    rmdir ($dir) || warn "Could not remove $dir: $!\n";
}

1;

### End VerifyHosts package.
