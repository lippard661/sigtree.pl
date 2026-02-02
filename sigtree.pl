#!/usr/bin/perl -w
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
# Modified 1 February 2026 to fix the actual underlying FD passing problem which was
#    improper assignment of worker sockets.

### Required packages.

# sigtree.pl requires the following in order to work:
# * Perl 5.
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
#   * Signify.pm wrapper for signify
# * If immutable flags are used (recommended for BSD):
#   BSD:
#   * /usr/bin/chflags (schg/noschg or uchg/nouchg)
#   * /sbin/sysctl kern.securelevel
#   Linux:
#   * /usr/bin/chattr (+i/-i)
#   * /usr/bin/lsattr
#   * /usr/bin/stat
# If privilege separation is used:
#   * JSON::MaybeXS or JSON::PP for IPC protocol
#   * IO::Handle, IO::Select, IO::Socket
#   * IO::FDPass
#   * Privileges::Drop
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

require 5.004;
use strict;
use feature 'state';
use Digest::SHA;
use Digest::SHA3;
use File::Basename;
# File::Temp is much larger than OpenBSD::MkTemp.
use if $^O ne "openbsd", "File::Temp", qw ( :mktemp tempfile );
use Getopt::Std;
# for privsep:
#use IO::Handle;
#use IO::Select;
use IO::Socket;
#use IO::Socket::UNIX; # not used unless reportnew subs are borrowed
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
my $TTY = '/usr/bin/tty';
my $BSD_SYS_IMMUTABLE_FLAG = 'schg';
my $BSD_USER_IMMUTABLE_FLAG = 'uchg';
my $LINUX_IMMUTABLE_FLAG = '+i';
my $LINUX_IMMUTABLE_FLAG_OFF = '-i';

my $VERSION = 'sigtree 1.22a of 1 February 2026';

# Now set in the config file, crypto_sigs field.
my $PGP_or_GPG = 'GPG'; # Set to PGP if you want to use PGP, GPG1 to use GPG 1, GPG to use GPG 2, signify to use signify.
my $ROOT_PGP_PATH = '/root/.pgp';
my $ROOT_GPG_PATH = '/root/.gnupg';
my $PGP_COMMAND = '/usr/local/bin/pgp';
my $GPG_COMMAND = '/usr/local/bin/gpg';
my $SIGTREE_SIGNIFY_PUBKEY = '/etc/signify/sigtree.pub';
my $SIGTREE_SIGNIFY_SECKEY = '/etc/signify/sigtree.sec';

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
my @READONLY_PROMISES = ('rpath');
my @READWRITE_PROMISES = ('wpath', 'cpath', 'tmppath');
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

# Get/set options.
getopts ('r:c:s:d:f:vhmpVD', \%opts) || die "sigtree.pl -h for help.\nUsage: sigtree.pl [options] command\n";

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
    print "-V show version (must be standalone option with no command)\n";
    print "-h help and show version\n";
    print "Commands:\n";
    print "initialize: Initialize specifications for a set of trees.\n";
    print "initialize_specs: Initialize specification for the specification dir.\n";
    print "changes: Show non-updated or reinitialized changes found by check.\n";
    print "check: Check specifications for a set of trees.\n";
    print "check_file: Check an individual file against a specification.\n";
    print "   (The file name is specified on the command line after \"check_file\".)\n";
    print "check_specs: Check specification for the specification dir.\n";
    print "update: Update specifications with changes found by check.\n";
    exit;
}

if ($#ARGV >= 0) {
    $command = $ARGV[0];
    $file = $ARGV[1] if ($#ARGV > 0);
}

if (!defined ($command) || ($command eq 'check_file' && $#ARGV != 1) ||
    ($command ne 'check_file' && $#ARGV != 0)) {
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
elsif ($command ne 'initialize' &&
       $command ne 'check') {
    die "Unknown command \"$command\".\n"
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
	open (my $outfh, '-|', $SYSCTL, 'kern.securelevel');
	$SECURELEVEL = <$outfh>;
	close ($outfh);
	chomp ($SECURELEVEL) if (defined ($SECURELEVEL));
	$SECURELEVEL =~ s/^.*=\s*//;
	if ($SECURELEVEL !~ /^\d$/) {
	    die "Immutable file flags do not appear to be supported by your operating system.\n";
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

    # Need rwc for sigtree files (and x for dirs). This doesn't work if $root_dir doesn't exist yet.
    unveil ($root_dir, 'rwxc');
    if (!-e $root_dir) {
	my $root_dir_dir = File::Basename::dirname ($root_dir);
	unveil ($root_dir_dir, 'rwxc');
    }

    # Need x for immutable flag setting and checking.
    # Need r to be able to detect existence for sigtree checks.
    # Need x on /bin/sh for execution of list command..
    # $SYSCTL absent because it's already been run.
    if ($use_immutable) {
	unveil ($CHFLAGS, 'rx');
	unveil ($LIST_FLAGS_CMD, 'rx');
	unveil ($BINSH, 'rx');
    }
    # Need x for crypto sign/verify and keys.
    if ($use_pgp) {
	if ($use_signify) {
	    unveil ($SIGNIFY, 'rx');
	    unveil ($signify_pubkey, 'r');
	    unveil ($signify_seckey, 'r');
	}
	else {
	    unveil ($PGP::Sign::PGPPATH, 'rx');
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
    # Need /tmp access.
    unveil ('/tmp', 'rwxc');

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
	print "File does not exist. $file\n" if (!-e $file);
	if ($file =~ /^\.\// || $file !~ /^\//) {
	    require Cwd;
	    my $cwd = Cwd::cwd();
	    $file =~ s/^\.\///;
	    $file = $cwd . '/' . $file;
	}
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
	pledge (@promises) || die "Cannot pledge read-only promises. $!\n";
    }
    show_changes ($config, $no_macos_app_contents, @sets);
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

    if (!$specs_only) {

	if ((!$use_privsep && -e $changed_file) ||
	    ($use_privsep && grep { $_ eq $changed_file } @EXISTING_SPECS)) {
	    $changed_file_exists = 1;
	    $changedfile = new ChangedFile ($changed_file);
	    unless ($changedfile) {
		warn "Failed to load changed file, treating it as if it doesn't exist.\n";
		$changed_file_exists = 0;
	    }
	    $changed_specs = $changedfile->tree_present ($spec_dir);
	    if ($verbose) {
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
	if ($#specified_trees < $fork_children) {
	    $fork_children = $#specified_trees;
	    $fork_children = 0 if ($#specified_trees == 1);
	}

	# Track available worker slots
	my @available_workers = (0 .. $fork_children - 1);  # Initially all available
	my %worker_in_use;  # Track which workers are busy

	# Split this up among children. This children will produce some
	# output if verbose but don't need to coordinate with the parent
	# like in check_sets.
	if ($fork_children) {
	    # create $child_temp_dir with mktemp
	    $child_temp_dir = mkdtemp ('/tmp/sigtree.XXXXXXXX');
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
			
		    if (defined ($tree_ref) || defined ($ident)) {
			if (defined ($tree_ref)) {
			    $child_tree = ${$tree_ref};
			}
			else {
			    print "Warning: using ident $ident instead of tree ref for child $pid.\n";
			    $child_tree = $ident;
			}
			# Need to do this check again, only remove if it was in a specified set.
			if ($config->tree_uses_sets ($child_tree, @sets) &&
			    $changed_file_exists && $changedfile->tree_present ($child_tree)) {
			    $changedfile->delete ($child_tree);
			}
		    }
		    else {
			# child failed
			print "Warning: child pid $pid did not return a tree name or ident, exit code $exit_code.\n";
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
		    
		    # Don't close other worker sockets - just mark them unusable
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
	rmdir ($child_temp_dir);
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
		$changedfile->delete ($tree) if (!grep (/^$tree$/, @trees));
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
    my ($config, $no_macos_app_contents, @sets) = @_;
    my ($changedfile, $displayed_something, @changed_trees, $tree,
	@times, @users, @paths, @attrs, $time, $user, $path, $attr);

    if ((!$use_privsep && !-e $changed_file) ||
	($use_privsep && !grep { $_ eq $changed_file } @EXISTING_SPECS)) {
	die "There is no changed file.\n";
    }

    $changedfile = new ChangedFile ($changed_file);
    unless ($changedfile) {
	die "Failed to load changed file: $changed_file\n";
    }

    $displayed_something = 0;

    @changed_trees = $changedfile->get_trees;

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
	    # This code did try to display changed attrs (from $changedfile->get_set_changed_attrs),
	    # but that subroutine takes a set, not a tree, as an argument.  We aren't looking at
	    # sets unless the details are displayed.
	    foreach $path (@paths) {
		if (!$no_macos_app_contents ||
		    $path !~ /$MACOS_APP_CONTENTS/) {
		    if ($no_macos_app_contents && $path =~ /$MACOS_APP/) {
			print "   $path (macOS app)\n";
		    }
		    else {
			print "   $path\n";
		    }
		}
	    }
	}
    }

    if (!$displayed_something) {
	print "No trees in sets specified have been changed prior to last check.\n";
    }
    elsif ($verbose) {
	# Args are changedfile, verbose flag, write flag, no_macos_app_contents
	show_change_details ($changedfile, 0, 0, $no_macos_app_contents);
    }
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
	@trees, $tree, $quoted_tree, $tree_spec_name,
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
    unless ($changed_file) {
	die "Failed to load changed file: $changed_file\n";
    }

    # Clear the current contents of the changed file.
    $changedfile->reset_changed_file;

    print "Checking for extraneous files in specification dir.\n" if ($verbose);
    display_extraneous_files ($config, $spec_dir, $verbose);

    print "Checking to see if specification dir has changed.\n" if ($verbose);
    print "$spec_dir\n" if ($verbose);
    if ($use_pgp) {
	sigtree_verify ("$spec_dir_dir/$spec_spec");
    }
    check_tree ($config, $TREE_ROOT, $spec_dir, '.', '', $changedfile, "$spec_dir_dir/$spec_spec");

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
	    $quoted_tree = $trees[0];
	    $quoted_tree =~ s/\//\\\//;
	    $quoted_tree =~ s/\./\\\./;
	    $path =~ s/^$quoted_tree\///;
	}
    }
    else {
	@trees = $config->all_trees;
	$path = '.';
    }

    # Make check behave like initialize.
    foreach $tree (@trees) {
	push (@specified_trees, $tree) if ($config->tree_uses_sets ($tree, @sets));
    }
    # Don't fork unnecessarily.
    if ($#specified_trees < $fork_children) {
	$fork_children = $#specified_trees;
	$fork_children = 0 if ($#specified_trees == 1);
    }
    
    # Track available worker slots
    my @available_workers = (0 .. $fork_children - 1);  # Initially all available
    my %worker_in_use;  # Track which workers are busy
    
    if ($fork_children) {
	# create $child_temp_dir with mktemp
	$child_temp_dir = mkdtemp ('/tmp/sigtree.XXXXXXXX');
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
        
		if (defined ($tempfile_ref)) {
		    # Get the returned filename.
		    $child_temp_file = ${$tempfile_ref};
		    # Retrieve from stored.
		    $child_changedfile = new ChangedFile ("$child_temp_dir/$child_temp_file");
		    if ($child_changedfile) {
			# Merge into main one.
			$changedfile->merge ($child_changedfile);
		    }
		    else {
			warn "Failed to load child changed file: $child_temp_dir/$child_temp_file\n";
		    }
		    # Remove the file.
		    unlink ("$child_temp_dir/$child_temp_file");
		}
		else {
		    # child failed
		    # what's the recovery here?
		    print "Warning: child $pid ($ident) did not return a changedfile, exit code $exit_code.\n";
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
		warn "CHILD: [PID $$] checking tree $tree, using worker socket $current_worker_id\n" if ($main::debug_flag);
		
		# Set socket we use.
		$FileAttr::PRIV_IPC = $WORKER_SOCKETS[$current_worker_id];

		# Verify we got the right socker.
		warn "CHILD: PID $$ FileAttr::PRIV_IPC = " . fileno($FileAttr::PRIV_IPC) . "\n" if ($main::debug_flag);

		# Clear this array entry so Perl doesn't auto-close it later
		$WORKER_SOCKETS[$current_worker_id] = undef;

		# Close sockets we don't need.
		close $MAIN_PRIV_SOCK;
		for my $idx (0..$#WORKER_SOCKETS) {
		    if ($idx != $current_worker_id) {
			warn "CHILD: [PID $$] closing worker socket $idx (fd " . fileno($WORKER_SOCKETS[$idx]) . ")\n" if ($main::debug_flag);
			close $WORKER_SOCKETS[$idx];
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
	    $changedfile = new ChangedFile ("$child_temp_dir/$child_temp_file");
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
	rmdir ($child_temp_dir);
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
	# Only if it previously existed and is empty; the new changes haven't been
	# stored yet.
	$changedfile->delete_if_empty if ($write_flag &&
					  ((!$use_privsep && -e $changed_file) ||
					   ($use_privsep &&
					    grep { $_ eq $changed_file } @EXISTING_SPECS)));
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
	    ($priority, $description, $changes, $additions, $deletions) = $changedfile->get_set_info ($set);
	    print "\n$description (set $set, priority $priority)\n";
	    print "Changes: $changes, Additions: $additions, Deletions: $deletions\n";
	    if ($changes > 0) {
		print "Changes:\n";
		@paths = $changedfile->get_set_changes ($set);
		@attrs = $changedfile->get_set_changed_attrs ($set);
		foreach $path (@paths) {
		    if (!$no_macos_app_contents || $path !~ /$MACOS_APP_CONTENTS/) {
			$attr = shift (@attrs);
			print "   $path ($attr)\n";
		    }
		}
	    }
	    if ($additions > 0) {
		print "Additions:\n";
		@paths = $changedfile->get_set_additions ($set);
		foreach $path (@paths) {
		    if (!$no_macos_app_contents || $path !~ /$MACOS_APP_CONTENTS/) {
			print "   $path\n";
		    }
		}
	    }
	    if ($deletions > 0) {
		print "Deletions:\n";
		@paths = $changedfile->get_set_deletions ($set);
		foreach $path (@paths) {
		    if (!$no_macos_app_contents || $path !~ /$MACOS_APP_CONTENTS/) {
			print "   $path\n";
		    }
		}
	    }
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

    $macos_OK_flag = (!$no_macos_app_contents ||
		      $path !~ /$MACOS_APP_CONTENTS/);

    ($description, $keywords, $priority) = $config->set_info ($primary_set);

    %differences = $fileattr->compare ($fileattr2, $keywords);

    if ($differences{'any'}) {
	$changedfile->add ($tree, $path, $primary_set, %differences);

	$fileattr->display_diffs ($primary_set, $priority, %differences) if ($verbose);
    }
    elsif ($differences{'mtimestasis'}) { # special case for where only change is a noticeable lack of change.
	$fileattr->display_diffs ($primary_set, $priority, %differences) if ($verbose && $macos_OK_flag);
    }

    # Deleted files are a special case.  We walk through them.  (Which
    # means we walk both the old tree structure and the new tree
    # structure.
    if ($differences{'deleted_files'}) {
	foreach $file (@{$differences{'deleted_files'}}) {
	    $full_path = $file;
	    if (!$tree_root) {
	        $full_path = $path . '/' . $file;
            }
            check_tree ($config, $SUBTREE, $tree, $full_path, $spec, $changedfile);
	}
    }

    if ($fileattr2->{TYPE} eq 'dir') {
        foreach $file (@{$fileattr2->{FILES}}) {
	    $full_path = $file;
	    if (!$tree_root) {
	        $full_path = $path . '/' . $file;
            }
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
		print "   $changed_path\n" if ($changed_path ne '');
	    }
	    # Instead of aborting, why not continue to update these?	    
	    #	    return;
	    print "Will attempt to update all changed trees.\n";
	    $something_to_update = 1;
	    # Need to remove the spec dir from the list, but do it after other changes,
	    # not here.
	}
	elsif (!grep (/^$tree$/, @config_trees)) {
	    print "Warning: changed file contains tree \"$tree\" which is not in config. Removing from changed file.\n";
	    $changedfile->delete ($tree);
	    # Save changes (deletions).
	    $changedfile->store_changedfile;
	    # And delete the changed file if it's now empty.
	    $changedfile->delete_if_empty;
	    $removed_old_trees = 1;
	}
	elsif ($config->tree_uses_sets ($tree, @sets)) {
	    $something_to_update = 1;
	    last;
	}
    }
    die "Nothing changed in specified sets to update.\n" if (!$something_to_update);

    $pgp_passphrase = get_pgp_passphrase() if ($use_pgp);

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
		PrivSep::request_immutable_set ($MAIN_PRIV_SOCK, $spec_dir, $IMMUTABLE_OFF);
		PrivSep::request_immutable_set ($MAIN_PRIV_SOCK, "$spec_dir/$tree_spec_name", $IMMUTABLE_OFF);
		if ($use_pgp) {
		    PrivSep::request_immutable_set ($MAIN_PRIV_SOCK, "$spec_dir/$tree_spec_name.sig", $IMMUTABLE_OFF);
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
		print "Failed to load spec for $tree, skipping.\n";
		return;
	    }
	    
	    @changed_paths = $changedfile->get_paths ($tree);
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
		    print "Warning: There are no longer changes to path $full_path.\n" if ($macos_OK_flag);
		}
		elsif ($differences{'deleted'}) {
		    print "   Deleting $path.\n" if ($verbose && $macos_OK_flag);
		    $spec->delete ($tree, $changed_path);
		}
		else {
		    if ($differences{'added'} && $differences{'type'} eq 'nonexistent') {
			print "   No change made to spec for $path.\n" if ($verbose && $macos_OK_flag);
		    }
		    else {
			print "   Adding $path.\n" if ($verbose && $differences{'added'} && $macos_OK_flag);
			print "   Updating $path.\n" if ($verbose && !$differences{'added'} && $macos_OK_flag);
			$spec->update ($tree, $changed_path, $fileattr2);
		    }
		}
	    }

	    # Save the changed spec.
	    $spec->store_spec ("$spec_dir/$tree_spec_name");

	    # Now updated; delete this tree from the changed file.
	    $changedfile->delete ($tree);

	    # Save changes (deletions).
	    $changedfile->store_changedfile;

	    # And delete the changed file if it's now empty.
	    $changedfile->delete_if_empty;

	    if ($use_pgp) {
		sigtree_sign ("$spec_dir/$tree_spec_name", $pgp_passphrase);
	    }
	    if ($use_privsep && $use_immutable) {
		PrivSep::request_immutable_set ($MAIN_PRIV_SOCK, "$spec_dir/$tree_spec_name", $IMMUTABLE_ON);
		if ($use_pgp) {
		    PrivSep::request_immutable_set ($MAIN_PRIV_SOCK, "$spec_dir/$tree_spec_name.sig", $IMMUTABLE_ON);
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
	PrivSep::request_immutable_set ($MAIN_PRIV_SOCK, "$spec_dir_dir/$spec_spec", $IMMUTABLE_OFF);
	if ($use_pgp) {
	    PrivSep::request_immutable_set ($MAIN_PRIV_SOCK, "$spec_dir_dir/$spec_spec.sig", $IMMUTABLE_OFF);
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
	PrivSep::request_immutable_set ($MAIN_PRIV_SOCK, $spec_dir, $IMMUTABLE_ON);
    }
    elsif ($use_immutable) {
	set_immutable_flag ($spec_dir, $IMMUTABLE_ON);
    }
    create_tree ($config, $TREE_ROOT, $spec_dir, '', '', "$spec_dir_dir/$spec_spec");
    if ($use_pgp) {
	sigtree_sign ("$spec_dir_dir/$spec_spec", $pgp_passphrase);
    }
    if ($use_privsep && $use_immutable) {
	PrivSep::request_immutable_set ($MAIN_PRIV_SOCK, "$spec_dir_dir/$spec_spec", $IMMUTABLE_ON);
	if ($use_pgp) {
	    PrivSep::request_immutable_set ($MAIN_PRIV_SOCK, "$spec_dir_dir/$spec_spec.sig", $IMMUTABLE_ON);
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
    elsif (-e $spec_dir_dir . "$spec_spec") {
	if (!-r $spec_dir_dir . "/$spec_spec") {
	    die "Host specification is not readable. $spec_dir_dir/$spec_spec.\n";
	}
	elsif ($caller != $CHECK && !-w $spec_dir_dir . "/$spec_spec") {
	    die "Host specification is not writable. $spec_dir_dir/$spec_spec\n";
	}
    }
    elsif ($caller != $CHECK && $use_immutable && $SECURELEVEL != 0 && ($immutable_flag ne $BSD_USER_IMMUTABLE_FLAG)) {
	die "Cannot write to existing host specification when kernel securelevel > 0.  Securelevel = $SECURELEVEL\n";
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
}

# Subroutine to display list of extraneous files in the specification dir.
sub display_extraneous_files {
    my ($config, $spec_dir, $verbose) = @_;
    my (@extraneous_files, $file);

    @extraneous_files = _identify_extraneous_files ($config, $spec_dir);
    if ($#extraneous_files >= 0) {
	print "The following extraneous files were found in the specification dir $spec_dir.\n";
	foreach $file (@extraneous_files) {
	    print "   $file\n";
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
	opendir (DIR, $spec_dir);
	@files = grep (!/^\.{1,2}$/, readdir (DIR));
	closedir (DIR);
	
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

    if (-w $file && ($SECURELEVEL == 0 || !immutable_file ($file))) {
	return 1;
    }
    # If file doesn't exist, dir must be writable.  We don't
    # auto-create dirs, so this isn't a recursive function.
    elsif (!-e $file) {
	$dir = File::Basename::dirname ($file);
	if (-w $dir && ($SECURELEVEL == 0 || !immutable_file ($dir))) {
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
	chop ($answer);

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

# Subroutine to set immutable flag.
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
	if ($bsd) {
	    system ($CHFLAGS, $flag, $path);
	}
	elsif ($linux && !-l $path) {
	    system ($CHATTR, '-f', $flag, $path);
	}

	if (!$on && !writable_file ($path)) {
	    print "Unable to reset immutable flag on $path.\n";
	    exit;
	}
    }
}

# Subroutine to get PGP passphrase.
sub get_pgp_passphrase {
    my ($pgp_passphrase, $current_tty, $temp_file);

    if ($PGP_or_GPG eq 'PGP' || $PGP_or_GPG eq 'GPG1' || $PGP_or_GPG eq 'signify') {
	system ($STTY, '-echo');
	print "$PGP_or_GPG Passphrase: ";
	$pgp_passphrase = <STDIN>;
	print "\n";
	system ($STTY, 'echo');
	chop ($pgp_passphrase);
	return ($pgp_passphrase);
    }
    elsif ($PGP_or_GPG eq 'GPG') { # gpg-agent does the work when we sign something, so sign a temp file.
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
	sigtree_pgp_sign ($temp_file, $pgp_passphrase); # can skip the wrapper
	unlink ($temp_file);
	unlink ("$temp_file.sig");
	return ($pgp_passphrase);
    }
    else {
	die "Unexpected value for PGP_or_GPG: $PGP_or_GPG\n";
    }
}

# Generic wrapper for signing.
sub sigtree_sign {
    my ($file, $pgp_passphrase) = @_;

    if ($use_privsep) {
	PrivSep::request_sign_file ($MAIN_PRIV_SOCK,
				    $file, $pgp_passphrase,
				    $use_signify,
				    $signify_seckey);
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
	PrivSep::request_verify_signature ($MAIN_PRIV_SOCK,
					   $file,
					   $use_signify,
					   $signify_pubkey);
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

    if (open (FILE, '<', $file)) {
	while (<FILE>) {
	    push (@data, $_);
	}
	close (FILE);
    }
    else {
	print "Could not read $file to create $PGP_or_GPG signature.\n";
	return;
    }

    ($signature, $version) = &PGP::Sign::pgp_sign ($config->{PGPKEYID}, $pgp_passphrase, @data);

    if (!defined ($signature)) {
	@errors = &PGP::Sign::pgp_error;
	die "@errors";
    }

    if (open (FILE, '>', "$file.sig")) {
	print FILE "$signature\n";
	close (FILE);
    }
    else {
	print "Could not write $file.sig to create $PGP_or_GPG signature.\n";
	return;
    }
}

# Verify a PGP signature.
sub sigtree_pgp_verify {
    my ($file) = @_;
    my ($signer, $signature, $version, @data, @errors);
    # $version is left undefined.

    if (open (FILE, '<', $file)) {
	while (<FILE>) {
	    push (@data, $_);
	}
	close (FILE);
    }
    else {
	print "Cannot open file $file to verify $PGP_or_GPG signature.\n";
	return;
    }
    if (open (FILE, '<', "$file.sig")) {
	while (<FILE>) {
	    $signature .= $_;
	}
	close (FILE);
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
sub sigtree_signify_sign {
    my ($file, $signify_passphrase) = @_;
    my (@errors);
    my $SKIP_SIGNIFY_CHECK = 1;

    if (Signify::sign ($file, $signify_passphrase, $signify_seckey, $SKIP_SIGNIFY_CHECK)) {
	return;
    }

    @errors = Signify::signify_error();

    if ($errors[0] =~ /^no readable file/) {
	print "Could not read $file to create $PGP_or_GPG signature.\n";
    }
    elsif ($errors[0] =~ /^cannot write signature file/) {
	print "Could not write $file.sig to create $PGP_or_GPG signature.\n";
    }
    elsif ($errors[0] =~ /^no readable secret key/) {
	print "Could not read secret key $signify_seckey to create $PGP_or_GPG signature.\n";
    }
    else {
	print "@errors";
    }
    return;
}

# Verify a signify signature on a specification.
sub sigtree_signify_verify {
    my ($file) = @_;
    my (@errors);
    my $SKIP_SIGNIFY_CHECK = 1;

    if (Signify::verify ($file, $signify_pubkey, $SKIP_SIGNIFY_CHECK)) {
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
        # PRIVILEGED PARENT PROCESS
        # This process stays as root
        
        # Close worker ends (we don't need them)
        close $main_worker_sock;
        close $_ for @worker_socks;

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
		# ACK protocol only on Linux.
		if ($^O eq 'linux') {
		    warn "[DEBUG] [PRIVILEGED PARENT] Waiting for ACK before sending FD\n" if ($main::debug_flag);
		    my $ack_buf;
		    # Timeout.
		    eval {
			local $SIG{ALRM} = sub { die "ACK timeout\n"; };
			alarm (5); # 5 second timeout
			my $n = sysread ($sock, $ack_buf, 3);
			alarm (0);
		    
			unless ($n == 3 && $ack_buf eq 'ACK') {
			    warn "[PRIVILEGED PARENT] Failed to receive ACK for FD transfer (got '$ack_buf', $n bytes)\n";
			    close $response_filehandle;
			    next;
			}
		    };
		    if ($@) {
			warn "[PRIVILEGED PARENT] ACK timeout or error: $@\n";
			close $response_filehandle;
			next;
		    }
		}

		# Now send the FD
		IO::FDPass::send(fileno($sock), $response_fd_to_send);

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
    
    my $type = $request->{type};
    my $path = $request->{path};

    my @TREE_REQUESTS = ('OPEN', 'STAT', 'READDIR', 'READLINK',
			 'IMMUTABLE_GET');
    my @SIGTREE_FILE_REQUESTS = ('IMMUTABLE_SET', 'DELETE_FILE',
				 'SIGN_FILE', 'VERIFY_SIGNATURE');

    print "DEBUG: [PRIVILEGED PARENT] Received request $type $path\n" if ($main::debug_flag);

    # Validate path for all tree requests OR sigtree file requests.
    if (grep { $_ eq $type } @TREE_REQUESTS) {
	unless (is_allowed_path($path)) {	   
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
    
    # Open file as root
    unless (open($fh, $mode, $path)) {
        return { error => "$! ($path)" };
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
        return { error => "$! ($path)" };
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
    
    return {
        success => 1,
        entries => \@entries
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
    
    return {
        success => 1,
        target => $canonical_target,
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
    
    # Call existing set_immutable_flag function
    set_immutable_flag($path, $immutable);
    
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
    my $pgp_passphrase = $request->{passphrase};
    my $use_signify = $request->{use_signify};
    my $signify_seckey = $request->{signify_seckey};
    
    # Call the appropriate signing function
    eval {
        if ($use_signify) {
            main::sigtree_signify_sign($file, $pgp_passphrase, $signify_seckey);
        } else {
            main::sigtree_pgp_sign($file, $pgp_passphrase);
        }
    };
    
    if ($@) {
        return { error => "Signing failed: $@" };
    }
    
    # Ensure .sig file is root-owned
    my $sig_file = "$file.sig";
    if (-e $sig_file) {
        chown(0, 0, $sig_file);
    }
    
    return { success => 1 };
}

sub handle_verify_signature_request {
    my ($request) = @_;
    my $file = $request->{path};
    my $use_signify = $request->{use_signify};
    my $signify_pubkey = $request->{signify_pubkey};
    
    # Call the appropriate verification function
    my $result;
    eval {
        if ($use_signify) {
            $result = main::sigtree_signify_verify($file, $signify_pubkey);
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
    
    # Only allow writes to:
    # - Spec files in $spec_dir (per-host)
    # - Spec spec file in $spec_dir_dir
    # - Changed files in $spec_dir_dir (*.changed, *.changedsec)
    # - NOT arbitrary files in $root_dir (no longer used for changed files)
    
    # Check if path is in spec_dir (per-host specs)
    if (defined $spec_dir) {
        return 1 if $path =~ m{^\Q$spec_dir\E/};
        return 1 if $path eq $spec_dir;
    }
    
    # Check if path is in spec_dir_dir (shared parent for multi-host)
    if (defined $spec_dir_dir) {
        # Allow the directory itself
        return 1 if $path eq $spec_dir_dir;
        
        # Allow spec spec file (e.g., hostname.spec(sec) in spec_dir_dir)
        return 1 if $path =~ m{^\Q$spec_dir_dir\E/[^/]+\.spec$};
	return 1 if $path =~ m{^\Q$spec_dir_dir\E/[^/]+\.specsec$};
        return 1 if $path =~ m{^\Q$spec_dir_dir\E/[^/]+\.sig$};
        
        # Allow changed files in spec_dir_dir
        return 1 if $path =~ m{^\Q$spec_dir_dir\E/[^/]+\.changed$};
        return 1 if $path =~ m{^\Q$spec_dir_dir\E/[^/]+\.changedsec$};
    }
    
    # Also explicitly check for the spec files
    if (defined ($spec_dir)) {
	return 1 if $path =~ m{^\Q$spec_dir\E/.*\.spec$};
	return 1 if $path =~ m{^\Q$spec_dir\E/.*\.sig$};
    }
    
    return 0;
}

# Is it in the configured trees OR in the sigtree files?
sub is_allowed_path {
    my ($path) = @_;
    
    # Path must be absolute
    return 0 unless $path =~ m{^/};
    
    # Check against configured trees (loaded from config)
    # Get this from the global $config object
    # Note: This function runs in privileged parent, so it needs
    # access to the tree list. Pass it during setup.
    
    for my $tree (@ALLOWED_TREES) {
        return 1 if $path =~ m{^\Q$tree\E(/|$)};
    }
    
    return 0;
}

### END Privilege separation subroutines (main program, also see separate PrivSep package below).

### Config package.

# Runs privileged and would require some changes to run unprivileged.

# Methods to handle config file object.
package Config;

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
			'flags'
			);

    my $DEFAULT_KEYWORDS = 'gid,mode,nlink,shadigest,uid,size,link,mtime,ctime,type,flags';

    my ($self, $state, $line, $raw_line, $field, $value);
    my ($set_long_name, $set_short_name, %used_set_names, %set_has_members,
	$current_set, @keywords, $keyword, $path, $set_list,
	@sets, $set_name, $arg_no, $error, %used_tree_paths, $current_tree,
	%used_exception_paths, %used_tree_exception_paths, $tree, $other_tree);

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

    open (CONFIG, '<', $config_file) ||
	die "Cannot open config file. $!. $config_file\n";
    while (<CONFIG>) {
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
		if ($value =~ /^\d+/) {
		    die "\"max_child_procs:\" field must be zero or an integer >= 2, line $line. $config_file\nLine: $raw_line" if ($value == 1);	    
		    $self->{MAX_CHILD_PROCS} = $value;
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
		if ($value =~ /^\d+/) {
		    die "\"default_child_procs:\" field must be zero or an integer >= 2, line $line. $config_file\nLine: $raw_line" if ($value == 1);
		    $self->{DEFAULT_CHILD_PROCS} = $value;
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

                %used_exception_paths = ();
	    }
	    elsif ($field eq 'exception' || $field eq 'exception-tree') {
		if ($state != $TREES_LIST) {
		    die "An \"$field:\" field in wrong section, line $line. $config_file\nLine: $raw_line";
		}
		if ($value !~ /^.*:[\w-]+$/) {
		    die "Invalid \"$field:\" field, line $line. $config_file\nLine: $raw_line";
		}
		if (!-d $current_tree) {
		    die "An \"$field:\" field defined for a non-directory tree \"$current_tree\", line $line. $config_file\nLine: $raw_line";
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
		if (($used_exception_paths{"$current_tree/$path"} && $field eq 'exception') ||
		    ($used_tree_exception_paths{"$current_tree/$path"} && $field eq 'exception-tree')) {
		    die "Second \"$field:\" field \"$path\" for tree \"$current_tree\", line $line. $config_file\nLine: $raw_line";
		}

		# Don't allow ..; . is allowed only for "exception:".
		if ($path eq '..' || ($path eq '.' && $field eq 'exception-tree')) {
		    die "Cannot use \"$path\" in \"$field:\" field for tree \"$current_tree\", line $line. $config_file\nLine: $raw_line";
		}

		if ($field eq 'exception-tree') {
		    $used_tree_exception_paths{"$current_tree/$path"} = 1;
		    $self->{TREE_DIR_EXCEPTION_SETS}->{$current_tree}->{$path} = _set_array_to_set_list (@sets);
		}
		else {
		    $used_exception_paths{"$current_tree/$path"} = 1;
		    $self->{TREE_EXCEPTION_SETS}->{$current_tree}->{$path} = _set_array_to_set_list (@sets);
		}
		# Move the test for directory or existence here, after it's set up, so we can respect the "ignore" keyword.
		if (!$self->path_is_ignored ($current_tree, $path)) {
		    if ($field eq 'exception-tree' && !-d $current_tree . '/' . $path) {
			print "Warning: Path \"$path\" in \"$field:\" field for tree \"$current_tree\" is not a directory or is inaccessible, line $line. $config_file\nLine: $raw_line";			
		    }
		    elsif ($field ne 'exception-tree' && !-e $current_tree . '/' . $path) {
			print "Warning: Path \"$path\" in \"$field:\" field for tree \"$current_tree\" does not exist or is inaccessible, line $line. $config_file\nLine: $raw_line";		    
		    }
		}
	    }
	    else {
		die "Invalid field \"$field\", line $line. $config_file\nLine: $raw_line";
	    }
	} # non-comment and non-blank line
    }
    close (CONFIG);

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
    if (substr ($tree, 0, length ($root_dir)) eq $root_dir) {
	return ('sigtree');
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
    my ($tree, $quoted_tree);

    foreach $tree (@{$self->{TREES}}) {
	$quoted_tree = $tree;
	$quoted_tree =~ s/\//\\\//;
	$quoted_tree =~ s/\./\\\./;
	if ($path eq $tree || $path =~ /^$quoted_tree\//) {
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

    while ($written < $total) {
	my $n = syswrite ($sock, $data, $total - $written, $written);
	if (!defined $n) {
	    warn "send_request: syswrite failed: $!\n";
	    return;
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
    my $MAX_REQUEST_LENGTH = 1024 * 1024;
    # Previously was 10MB (10_000_000)
    
    # Read 4-byte length
    my $len_packed;
    my $bytes_read = sysread($sock, $len_packed, 4);
    
    return undef unless $bytes_read == 4;
    
    my $len = unpack('N', $len_packed);
    
    # Sanity check
    return undef if $len > $MAX_REQUEST_LENGTH;  # 10MB max
    
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

    while ($written < $total) {
	my $n = syswrite ($sock, $data, $total - $written, $written);
	if (!defined $n) {
	    warn "send_response: syswrite failed: $!\n";
	    return;
	}
	$written += $n;
    }
}

# Subroutine to receive a response on the nonprivileged side.
sub recv_response {
    my ($sock) = @_;
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

sub request_stat {
    my ($sock, $path) = @_;
    
    my $request = {
        type => 'STAT',
        path => $path,
    };
    
    send_request($sock, $request);
    my $response = recv_response($sock);
    
    if ($response->{error}) {
        warn "Privileged stat failed: $response->{error}\n";
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
    my ($sock, $path, $mode) = @_;
    $mode //= '<'; # Default to read
    
    my $request = {
        type => 'OPEN',
        path => $path,
	mode => $mode,
    };
    
    send_request($sock, $request);
    my $response = recv_response($sock);
    
    if ($response->{error}) {
	if ($mode eq '>') {
	    warn "Cannot write to $path: $response->{error}\n";
	}
	else {
	    warn "Privileged open failed: $response->{error}\n";
	}
	return undef;
    }

    if ($response->{success}) {
	# ACK protocol only on Linux.
	if ($^O eq 'linux') {
	    warn "DEBUG: Sending ACK for FD transfer\n" if ($main::debug_flag);
	    # Send ACK to tell parent we're ready to receive FD (needed for Linux).
	    my $n = syswrite ($sock, 'ACK', 3);
	    if ($n != 3) {
		warn "Failed to send ACK: " . ($! || 'short write') . "\n";
	    }
	}
	
	# Now receive file descriptor from privileged parent
	my $fd = IO::FDPass::recv(fileno($sock));

	warn "DEBUG: [PID $$] After recv FD, got fd=$fd for $path\n" if ($main::debug_flag);

	if (!defined $fd || $fd < 0) {
	    warn "Failed to receive file descriptor for $path [PID $$]\n";
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
        warn "Privileged readdir failed: $response->{error}\n";
        return [];
    }
    
    return $response->{entries};
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
        warn "Privileged readlink failed: $response->{error}\n";
        return undef;
    }
    
    return ($response->{target}, $response->{target_type});;
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
        warn "Privileged immutable check failed: $response->{error}\n";
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
        die "Failed to set immutable flag on $path: $response->{error}\n";
    }
    
    return 1;
}

sub request_write_file {
    my ($sock, $path, $content, $mode) = @_;
    
    my $request = {
        type => 'WRITE_FILE',
        path => $path,
        content => $content,
        mode => $mode,
    };
    
    send_request($sock, $request);
    my $response = recv_response($sock);
    
    if ($response->{error}) {
        die "Failed to write file $path: $response->{error}\n";
    }
    
    return 1;
}

sub request_read_file {
    my ($sock, $path) = @_;
    
    my $request = {
        type => 'READ_FILE',
        path => $path,
    };
    
    send_request($sock, $request);
    my $response = recv_response($sock);
    
    if ($response->{error}) {
        warn "Failed to read file $path: $response->{error}\n";
        return undef;
    }
    
    return $response->{content};
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
    my ($sock, $file, $pgp_passphrase, $use_signify, $signify_seckey) = @_;
    
    my $request = {
        type => 'SIGN_FILE',
        path => $file,
        passphrase => $pgp_passphrase,
        use_signify => $use_signify,
        signify_seckey => $signify_seckey,
    };
    
    send_request($sock, $request);
    my $response = recv_response($sock);
    
    if ($response->{error}) {
        die "Failed to sign file $file: $response->{error}\n";
    }
    
    return 1;
}

sub request_verify_signature {
    my ($sock, $file, $use_signify, $signify_pubkey) = @_;
    
    my $request = {
        type => 'VERIFY_SIGNATURE',
        path => $file,
        use_signify => $use_signify,
        signify_pubkey => $signify_pubkey,
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

use Cwd qw( abs_path ); # used in _canonicalize_link_target
use Errno qw( EACCES EPERM );
use Fcntl ':mode'; # For S_IRUSR, S_IRGRP, S_IROTH, etc.
use File::Basename;
use File::Spec;

our $PRIV_IPC;
our %DIR_ACCESS_CACHE;

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
#    $self->{RDEV} = $stat[6]; # unused
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
	    $self->{SHADIGEST} = _get_sha_digest ($full_path, $sha_digest, $need_priv);
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

    # Get immutable flags if supported (may need privilege).
    $self->{FLAGS} = _get_file_flags ($full_path, $need_priv);

    bless $self, $class;
    return $self;
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
    my ($full_path, $sha_digest, $need_priv) = @_;
    my ($fh, $sha_version, $sha_bits, $digest);

    # Determine which SHA digest to use.
    if ($sha_digest =~ /-/) {
	($sha_version, $sha_bits) = split (/-/, $sha_digest);
    }
    else {
	return '<undefined>';
    }
    
    # If privsep is disabled, always open directly
    if (!$main::use_privsep) {
        if (!open ($fh, '<', $full_path)) {
            return undef;
        }
    }
    elsif ($need_priv) {
        # Request file descriptor from privileged parent
        $fh = PrivSep::request_open ($FileAttr::PRIV_IPC, $full_path);
        return undef unless $fh;
    }
    else {
        # Try to open unprivileged
        if (!open ($fh, '<', $full_path)) {
            # Unexpected - mode said we could read but we can't
            # Fall back to privileged
            $fh = PrivSep::request_open($FileAttr::PRIV_IPC, $full_path);
            return undef unless $fh;
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

    $digest->addfile ($fh);
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
    return 1 if ($fs_type eq 'fuse' || $fs_type eq 'msdos' ||
		 $fs_type eq 'tmpfs' || $fs_type eq 'mqueue' ||
		 $fs_type eq 'hugetlbfs' || $fs_type eq 'proc' ||
		 $fs_type eq 'devpts');
#    return 1 if ($fs_type ne 'ext2/ext3');
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
	# We do not set $differences{'any'} = 1 because this is a lack of change.
	# Reporting with -v needs to specialcase the presence of $differences{'mtimestasis'}.
    }
    if ($keywords{'ctime'} && ($self->_compare ($self->{CTIME}, $fileattr->{CTIME}))) {
	$differences{'ctime'} = $fileattr->{CTIME};
	$differences{'any'} = 1;
    }
    if ($keywords{'nlink'} && ($self->_compare ($self->{NLINK}, $fileattr->{NLINK}))) {
	$differences{'nlink'} = $fileattr->{nlink};
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

# Internal method to display a specific differing attribute.
sub _display_diff {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($attr, $original, $new) = @_;
    my ($spaces, $number, $unit);
    my %NUMBERS = (
		   1, 'one',
		   2, 'two',
		   3, 'three',
		   4, 'four',
		   5, 'five',
		   6, 'six',
		   7, 'seven',
		   8, 'eight',
		   9, 'nine',
		   10, 'ten'
		   );
    my %TIME_UNITS = (
		      's', 'second',
		      'm', 'minute',
		      'h', 'hour',
		      'd', 'day'
		      );

    if (!defined ($original)) {
	$original = '<undefined>';
    }
    if (!defined ($new)) {
	$new = '<undefined>';
    }

    if ($attr eq 'mode') {
	if ($original ne '<undefined>') {
	    $original = sprintf "%0lo", $original;
	    $original = substr ($original, 2, 4);
	}
	if ($new ne '<undefined>') {
	    $new = sprintf "%0lo", $new;
	    $new = substr ($new, 2, 4);
	}
    }
    elsif ($attr =~ /time/) {
	if ($original ne '<undefined>') {
	    $original = localtime ($original);
	}
	if ($attr eq 'modification time stasis') {
	    ($number, $unit) = split (/,/, $new);
	    $unit = $TIME_UNITS{$unit};
	    if ($number > 1) {
		$unit .= 's';
	    }
	    if ($number < 11) {
		$number = $NUMBERS{$number};
	    }
	    $new = "$number $unit";
	}
	elsif ($new ne '<undefined>') {
	    $new = localtime ($new);
	}
    }

    if (length ($original) > 20 || length ($new) > 20) {
	$spaces = length ($attr) + 14;
	if ($attr eq 'modification time stasis') {
	    print "   modification time has not changed from $original for more than\n";
	    printf "   %" . $spaces . "s%s\n", ' ', $new;
	}
	else {
	    print "   $attr changed from $original to\n";
	    printf "   %" . $spaces . "s%s\n", ' ', $new;
	}
    }
    else {
	if ($attr eq 'modification time stasis') {
	    print "   modification time has not changed from $original for more than $new.\n";
	}
	else {
	    print "   $attr changed from $original to $new.\n";
	}
    }
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
    print "\n   $display_path (set $primary_set, priority $priority)\n";
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

    if ($differences{'type'}) {
	print "   type changed from $self->{TYPE} to $differences{'type'}.\n";
    }
    if ($differences{'linktarget_type'}) {
	print "   link target type changed from $self->{LINKTARGET_TYPE} to $differences{'linktarget_type'}.\n";
    }
    if ($differences{'mode'}) {
	$self->_display_diff ('mode', $self->{MODE}, $differences{'mode'});
    }
    if ($differences{'uid'}) {
	$self->_display_diff ('uid', $self->{UID}, $differences{'uid'});
    }
    if ($differences{'gid'}) {
	$self->_display_diff ('gid', $self->{GID}, $differences{'gid'});
    }
    if ($differences{'size'}) {
	$self->_display_diff ('size', $self->{SIZE}, $differences{'size'});
    }
    if ($differences{'mtime'}) {
	$self->_display_diff ('modification time', $self->{MTIME}, $differences{'mtime'});
    }
    elsif ($differences{'mtimestasis'}) {
	$self->_display_diff ('modification time stasis', $self->{MTIME}, $differences{'mtimestasis'});
    }
    if ($differences{'ctime'}) {
	$self->_display_diff ('inode change time', $self->{CTIME}, $differences{'ctime'});
    }
    if ($differences{'nlink'}) {
	$self->_display_diff ('nlink', $self->{NLINK}, $differences{'nlink'});
    }
    if ($differences{'shadigest'}) {
	$self->_display_diff ('shadigest', $self->{SHADIGEST}, $differences{'shadigest'});
    }
    if ($differences{'flags'}) {
	$self->_display_diff ('flags', $self->{FLAGS}, $differences{'flags'});
    }
    if ($differences{'link'}) {
	$self->_display_diff ('symbolic link target', $self->{LINK}, $differences{'link'});
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

use Storable qw(fd_retrieve lock_retrieve lock_nstore nstore_fd);

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
	close ($fh);
    }
    else {
	lock_nstore ($self, $spec_path) or die "Failed to store spec to $spec_path: $!\n";
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

use Storable qw(fd_retrieve lock_retrieve lock_nstore nstore nstore_fd retrieve);

# Method to create a new changed file or read in its contents,
# and reset counters for check.
sub new {
    my $class = shift;
    my ($self);
    my ($changed_file) = @_;

    my $is_temp_file = ($changed_file =~ m{^/tmp/});
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
    }
    else {
	$self = _initialize_empty_changedfile ($changed_file);
    }

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
    $self->{PATH} = {};
    
    return $self;
}

# Method to reset the changed file in preparation for recreating it.
sub reset_changed_file {
    my $self = shift;
    my $class = ref ($self) || $self;

    $self->{CHANGES} = ();
    $self->{ADDITIONS} = ();
    $self->{DELETIONS} = (); 
    $self->{SET_TO_PATH_ADD} = (); 
    $self->{SET_TO_PATH_DEL} = (); 
    $self->{SET_TO_PATH_CHANGE} = (); 
    $self->{SET_TO_PATH_CH_ATTR} = ();
    $self->{PATH} = ();
}

# Method to add a path to the changed file (unless already present).
# Update counters for changes for this check.  Set is primary set.
sub add {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree, $path, $set, %differences) = @_;
    my ($full_path, $changed_attrs, $present_path);

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
        $changed_attrs = join (',', grep (!/^any$|^added|^deleted/, keys (%differences)));
        push (@{${$self->{SET_TO_PATH_CH_ATTR}}{$set}}, $changed_attrs);
    }


    foreach $present_path (@{${$self->{PATH}}{$tree}}) {
        return if ($path eq $present_path);
    }

    push (@{${$self->{PATH}}{$tree}}, $path);
}

# Method to add a new check time (and user) for a particular tree.
sub add_time {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree) = @_;

    push (@{${$self->{TIME}}{$tree}}, time());
    push (@{${$self->{USER}}{$tree}}, $USERNAME);
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
        }
    }

    # Get trees. Should be only one but this is more general.
    @trees = keys (%{$other->{PATH}});

    # Add trees and check times and users for each tree.
    foreach $tree (@trees) {
	push (@{${$self->{PATH}}{$tree}}, @{${$other->{PATH}}{$tree}});
	push (@{${$self->{TIME}}{$tree}}, @{${$other->{TIME}}{$tree}});
	push (@{${$self->{USER}}{$tree}}, @{${$other->{USER}}{$tree}});
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

    @times = @{${$self->{TIME}}{$tree}};
    return (@times);
}

# Method to return array of check users for a specific tree in the
# changed file.
sub get_users {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree) = @_;
    my (@users);

    @users = @{${$self->{USER}}{$tree}};
    return (@users);
}

# Method to delete a tree from the changed file.
sub delete {
    my $self = shift;
    my $class = ref ($self) || $self;
    my ($tree) = @_;

    delete (${$self->{PATH}}{$tree});
    delete (${$self->{TIME}}{$tree});
    delete (${$self->{USER}}{$tree});
}

# Method to delete the changed file if there are no changed trees left
# in it.
sub delete_if_empty {
    my $self = shift;
    my $class = ref ($self) || $self;
    my (@trees);

    @trees = keys (%{$self->{PATH}});
    if ($#trees < 0) {
	my $is_temp_file = ($self->{CHANGEDFILE} =~ m{^/tmp/});

	if ($main::use_privsep && !$is_temp_file) {
	    # Main changed file - needs privileged delete
	    PrivSep::request_delete_file ($FileAttr::PRIV_IPC,
					  $self->{CHANGEDFILE});
	}
	else {
	    unlink ($self->{CHANGEDFILE});
	}
    }
}

# Method to store changed file. Stores even if empty.
sub store_changedfile {
    my $self = shift;
    my $class = ref ($self) || $self;

    my $is_temp_file = ($self->{CHANGEDFILE} =~ m{^/tmp/});

    if ($main::use_privsep && !$is_temp_file) {
	# Main changed file - requires privileged write.
	my $fh = PrivSep::request_open ($FileAttr::PRIV_IPC,
					$self->{CHANGEDFILE},
					'>');
	unless ($fh) {
	    die "Failed to open changed file for writing via privsep: $self->{CHANGEDFILE}\n";
	}
	nstore_fd ($self, $fh);
	close ($fh);
    }
    elsif ($is_temp_file) {
	# No locking.
	nstore ($self, $self->{CHANGEDFILE})
	    or die "Failed to store child changed file: $!\n";
    }
    else {
	lock_nstore ($self, $self->{CHANGEDFILE})
	    or die "Failed to store changed file: $!\n";
    }
}

1;

### End ChangedFile package.
