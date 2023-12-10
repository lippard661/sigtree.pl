#!/usr/bin/perl -w
#
#########################################################################
#
# Copyright 2000-2022 by Jim Lippard.  Permission granted for free
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
# Home website location is http://www.discord.org/~lippard/software.
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
#    for secondary specifications.  Fixed bug in &writable_file when file
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
#    bug in &immutable_file which had BSD and Linux checks reversed.  Added
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
# Modified 3 December 2023 by Jim Lippard to use pledge and veil on OpenBSD.

### Required packages.

# sigtree.pl requires the following in order to work:
# * Perl 5.
# * Standard Perl modules File::Basename, Getopt::Std, Storable, and
#   Sys::Hostname.
# * CPAN module Digest::SHA
# * If PGP/GPG/signify signing is used (recommended):
#   * PGP 5 or later or GPG.
#   * CPAN module PGP::Sign.
#   * Or: /usr/bin/signify
#   * /bin/stty (for PGP or GPG 1, without gpg-agent)
#   * /usr/bin/tty (for GPG 2, with gpg-agent)
#   * /usr/bin/mktemp (for GPG 2, with gpg-agent)
# * If immutable flags are used (recommended for BSD):
#   BSD:
#   * /usr/bin/chflags (schg/noschg or uchg/nouchg)
#   * /usr/sbin/sysctl kern.securelevel
#   Linux:
#   * /usr/bin/chattr (+i/-i)
#   * /usr/bin/lsattr
#   * /sbin/runlevel
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
use Cwd;
use Digest::SHA;
use Digest::SHA3;
use File::Basename;
use Getopt::Std;
use PGP::Sign;
use Storable;
use Sys::Hostname;
use if $^O eq "openbsd", "OpenBSD::Pledge";
use if $^O eq "openbsd", "OpenBSD::Unveil";

### Global constants.

use vars qw( $SECURELEVEL );

$SECURELEVEL = 0;

my $BINSH = '/bin/sh'; # needed for unveil only
my $CHATTR = '/usr/bin/chattr';
my $LSATTR = '/usr/bin/lsattr';
my $CHFLAGS = '/usr/bin/chflags';
my $LIST_CMD = '/bin/ls';
my $LSFLAGS = "$LIST_CMD -lod";
my $MAC_LSFLAGS = "$LIST_CMD -lOd";
my $MKTEMP = '/usr/bin/mktemp';
my $SIGNIFY = '/usr/bin/signify';
my $ECHO = '/bin/echo'; # yuck
my $STTY = '/bin/stty';
my $SYSCTL = '/sbin/sysctl';
my $TTY = '/usr/bin/tty';
my $BSD_SYS_IMMUTABLE_FLAG = 'schg';
my $BSD_USER_IMMUTABLE_FLAG = 'uchg';
my $LINUX_IMMUTABLE_FLAG = '+i';
my $LINUX_IMMUTABLE_FLAG_OFF = '-i';

my $VERSION = 'sigtree 1.18a of 9 December 2023';

# Now set in the config file, crypto_sigs field.
my $PGP_or_GPG = 'GPG'; # Set to PGP if you want to use PGP, GPG1 to use GPG 1, GPG to use GPG 2, signify to use signify.
my $ROOT_PGP_PATH = '/root/.pgp';
my $ROOT_GPG_PATH = '/root/.gnupg';
my $SIGTREE_SIGNIFY_PUBKEY = '/etc/signify/sigtree.pub';
my $SIGTREE_SIGNIFY_SECKEY = '/etc/signify/sigtree.sec';

my $OSNAME = $^O;

if ($OSNAME eq 'darwin') {
    $LSFLAGS = $MAC_LSFLAGS;
}

my $HOSTNAME = hostname() || die "Hostname is undefined.\n";
my $DOMAIN = '';
($HOSTNAME, $DOMAIN) = split (/\./, $HOSTNAME, 2);

my $USERNAME = getpwuid($<);

my $ROOT_DIR = '/var/db/sigtree';
my $SYSCONF_DIR = '/etc';

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
    $root_dir,     # Root dir to use.
    $spec_dir_dir, # Directory containing specifications directories.
    $spec_dir,     # Specifications dir to use.
    $spec_spec,    # Specification for specifications dir.
    $secondary_specs, # Are we using secondary specs? If so, no PGP/immutable.
    $changed_file, # Changed specifications file to use.
    $config,       # Config file object.
    $set,          # List of sets to use.
    @sets,         # List of sets being processed.
    $arg_no,       # Used for returning error message on set list validation.
    $error,        # Ditto.
    $something_to_do, # Are any trees members of specified sets?
    $use_pgp,      # If PGP, GPG, or signify should be used.
    $use_signify,  # If signify should be used.
    $signify_pubkey, # signify public key file.
    $signify_seckey, # signify private key file.
    $use_immutable,# If system immutable flags should be used.
    $immutable_flag,# For BSD, which type of immutability to use.
    $verbose,      # If we should be verbose.
    );

### Main program.

# Get/set options.
getopts ('r:c:s:d:vh', \%opts) || die "sigtree.pl -h for help.\nUsage: sigtree.pl [options] command\n";

$root_dir = $opts{'r'} || $ROOT_DIR;
$spec_spec = $HOSTNAME . '.spec';
$config_file = $opts{'c'} || $SYSCONF_DIR . '/' . $HOSTNAME . '.sigtree.conf';
$config_file = $SYSCONF_DIR . '/' . $config_file if ($config_file !~ /^\.\/|^\//);
$set = $opts{'s'} || 0;
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
    $changed_file = $root_dir . '/' . $HOSTNAME . '.changedsec';
}
else {
    $changed_file = $root_dir . '/' . $HOSTNAME . '.changed';
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
    print "-v verbose\n";
    print "-h help and version\n";
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

if ($ARGV[0] ne 'initialize' &&
    $ARGV[0] ne 'initialize_specs' &&
    $ARGV[0] ne 'changes' &&
    $ARGV[0] ne 'check' &&
    $ARGV[0] ne 'check_file' &&
    $ARGV[0] ne 'check_specs' &&
    $ARGV[0] ne 'update') {
    die "Unknown command \"$ARGV[0]\".\n"
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
	&add_new_set_to_uninitialized_trees ($spec_dir);
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
	($PGP_or_GPG eq 'signify' && $config->{PGPKEYID} ne 'signify')) {
	die "Inconsistent crypto_sigs and pgpkeyid options in config file.\n";
    }
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
# been implemented.)
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
	$SECURELEVEL = `$SYSCTL kern.securelevel`;
	chop ($SECURELEVEL);
	$SECURELEVEL =~ s/^.*=\s*//;
	if ($SECURELEVEL !~ /^\d$/) {
	    die "Immutable file flags do not appear to be supported by your operating system.\n";
	}
    }
    elsif (-e $CHATTR) { # Linux
	# Get current runlevel from /sbin/runlevel.  First return arg is previous runlevel,
	# second return arg is current runlevel.

	# Perhaps ideally this whole section of code should be modified to check
	# to see if immutable flags can be set on and off, and refuse to allow it
	# if not.  Maybe later.
	$SECURELEVEL = `/sbin/runlevel`;
	if ($SECURELEVEL !~ /^\d+\s+(\d+)$/) {
	    die "Immutable file flags do not appear to be supported by your operating system.\n";
	}
	$SECURELEVEL = $1;
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

# If OpenBSD, use pledge and unveil.
# This is occurring after config parsing but before all argument and
# file validation, so it's not quite as narrowly specified as it could
# be, but if we did it later it would need to be a subroutine called
# before or by initialize_sets, check_sets, update_sets, and show_changes,
# and could be more narrowly tailored for each based on need to access
# all or a subset of trees or just what's in the sigtree root dir.
if ($OSNAME eq 'openbsd') {
    # fattr might not be necessary due to wpath
    pledge ('stdio,rpath,wpath,cpath,fattr,exec,unveil');
    # Need rwc for sigtree files.
    unveil ($root_dir, 'rwc');
    # Need x for immutable flag setting and checking.
    # Need r to be able to detect existence for sigtree checks.
    # Need x on /bin/sh for execution of list command.
    if ($use_immutable) {
	unveil ($CHFLAGS, 'rx');
	unveil ($LIST_CMD, 'rx');
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
	    }
	    else {
		unveil ($ROOT_GPG_PATH, 'rw');
	    }
	}

	# Need x for passphrase collection.
	unveil ($ECHO, 'rx');
	unveil ($STTY, 'rx');
	unveil ($TTY, 'rx');
    }
    # Need x for mktemp.
    unveil ($MKTEMP, 'rx');

    # Need r for all trees.
    my ($tree, @trees);
    @trees = $config->all_trees;
    foreach $tree (@trees) {
	unveil ($tree, 'r');
    }

    # Lock unveil.
    unveil ();
}

if ($ARGV[0] eq 'initialize') {
    &initialize_sets ($config, $ALL, @sets);
}
elsif ($ARGV[0] eq 'initialize_specs') {
    die "The -s option cannot be used with initialize_specs.\n" if ($opts{'s'});
    &initialize_sets ($config, $SPECS_ONLY, @sets);
}
elsif ($ARGV[0] eq 'changes') {
    &show_changes ($config, @sets);
}
elsif ($ARGV[0] eq 'check') {
    &check_sets ($config, $ALL, @sets);
}
elsif ($ARGV[0] eq 'check_file') {
    die "The -s option cannot be used with check_file.\n" if ($opts{'s'});
    print "File does not exist. $file\n" if (!-e $file);
    if ($file =~ /^\.\// || $file !~ /^\//) {
	$file =~ s/^\.\///;
	$file = cwd() . '/' . $file;
    }
    &check_sets ($config, $SUBTREE_ONLY, $file);
}
elsif ($ARGV[0] eq 'check_specs') {
    die "The -s option cannot be used with check_specs.\n" if ($opts{'s'});
    &check_sets ($config, $SPECS_ONLY, @sets)
}
elsif ($ARGV[0] eq 'update') {
    die "The -f option cannot be used with update.\n" if ($opts{'f'});
    &update_sets ($config, @sets);
}

### Subroutines.

# Subroutine to initialize sets.  We initialize all trees that contain
# any references to the sets specified--including exceptions that may
# not be members of those sets.
sub initialize_sets {
    my ($config, $specs_only, @sets) = @_;
    my ($pgp_passphrase, 
	$changed_file_exists, $changedfile, $changed_specs, @changed_trees,
	@trees, $tree, $tree_spec_name);

    $| = 1;

    if ($specs_only) {
	print "Warning: This command will cause any changes to your specifications dir\n";
	print "to be lost, and should only be used to wipe out changes which have\n";
	print "occurred to that dir for reasons such as a system dump (which causes\n";
	print "an inode change.  If you are at all uncertain, use the initialize\n";
	print "command to re-initialize all of the specifications themselves.\n";

	exit if (!&yes_or_no ('Proceed? '));
	
    }

    &verify_required_dirs ($INITIALIZE);
    
    $pgp_passphrase = &get_pgp_passphrase if ($use_pgp);

    # Remove any extraneous files from the specification directory.
    print "Removing extraneous files from specification dir.\n" if ($verbose);
    &remove_extraneous_files ($config, $spec_dir_dir, $spec_dir, $verbose, $use_immutable);

    if (!$specs_only) {
	if (-e $changed_file) {
	    $changed_file_exists = 1;
	    $changedfile = new ChangedFile;
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
	    $tree_spec_name = &path_to_spec ($tree);
### This "or" clause causes initialization of trees not in sets specified in -s. Is there any reason for it?
### It's possible, I suppose, for all sets to be specified and to have some trees in a changed file that
### aren't in any of those sets, if they've been removed from the config file... but that's a weird edge
### case that should be handled differently. There's already an option to initialize only what's in the
### changed file, it's called update.
###	    if ($config->tree_uses_sets ($tree, @sets) ||
###		($changed_specs && $changedfile->path_present ($spec_dir, $tree_spec_name))) {
	    if ($config->tree_uses_sets ($tree, @sets)) {
		if ($use_immutable) {
		    &set_immutable_flag ($spec_dir_dir, $IMMUTABLE_OFF);
		    &set_immutable_flag ($spec_dir, $IMMUTABLE_OFF);
		    &set_immutable_flag ("$spec_dir/$tree_spec_name", $IMMUTABLE_OFF);
		    if ($use_pgp) {
			&set_immutable_flag ("$spec_dir/$tree_spec_name.sig", $IMMUTABLE_OFF);
		    }
		}
		print "$tree\n" if ($verbose);
		&create_tree ($config, $TREE_ROOT, $tree, '.', '', "$spec_dir/$tree_spec_name");
		if ($use_pgp) {
			&sigtree_sign ("$spec_dir/$tree_spec_name", $pgp_passphrase);
		}
		if ($use_immutable) {
		    &set_immutable_flag ("$spec_dir/$tree_spec_name", $IMMUTABLE_ON);
		    if ($use_pgp) {
			&set_immutable_flag ("$spec_dir/$tree_spec_name.sig", $IMMUTABLE_ON);
		    }
		}

		# Remove this tree from the changed file if present.
		if ($changed_file_exists && $changedfile->tree_present ($tree)) {
		    $changedfile->delete ($tree);
		}
	    }
	}
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
	$changedfile->store_changedfile;
	$changedfile->delete_if_empty;
    }

    print "Initializing specification for specification dir.\n" if ($verbose);
    if ($use_immutable) {
	&set_immutable_flag ("$root_dir/$spec_spec", $IMMUTABLE_OFF);
	if ($use_pgp) {
	    &set_immutable_flag ("$root_dir/$spec_spec.sig", $IMMUTABLE_OFF);
	}
    }
    # This must be done before the specification for the specification dir
    # is created, since changing flags involves inode modification.
    if ($use_immutable) {
	&set_immutable_flag ($spec_dir, $IMMUTABLE_ON);
	&set_immutable_flag ($spec_dir_dir, $IMMUTABLE_ON);
    }
    &create_tree ($config, $TREE_ROOT, $spec_dir, '.', '', "$root_dir/$spec_spec");
    if ($use_pgp) {
	&sigtree_sign ("$root_dir/$spec_spec", $pgp_passphrase);
    }
    if ($use_immutable) {
	&set_immutable_flag ("$root_dir/$spec_spec", $IMMUTABLE_ON);
	if ($use_pgp) {
	    &set_immutable_flag ("$root_dir/$spec_spec.sig", $IMMUTABLE_ON);
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
	if (!&writable_file ($spec_path)) {
	    print "Specification is not writable. Skipping. $spec_path\n";
	    return;
	}
	($spec, $fileattr) = new Spec ($tree);
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
            &create_tree ($config, $SUBTREE, $tree, $full_path, $spec);
        }
    }
    if ($tree_root) {
	$spec->store_spec ($spec_path);
    }
}

# Subroutine to display contents of changed file (for specified sets).
sub show_changes {
    my ($config, @sets) = @_;
    my ($changedfile, $displayed_something, @changed_trees, $tree,
	@times, @users, @paths, @attrs, $time, $user, $path, $attr);

    if (!-e $changed_file) {
	die "There is no changed file.\n";
    }

    $changedfile = new ChangedFile;

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
		print "   $path\n";
	    }
	}
    }

    if (!$displayed_something) {
	print "No trees in sets specified have been changed prior to last check.\n";
    }
    elsif ($verbose) {
	# Args are changedfile, verbose flag, write flag.
	&show_change_details ($changedfile, 0, 0);
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
sub check_sets {
    my ($config, $specs_only, @sets) = @_;
    my ($subtree_only, $changedfile, @trees, $tree, $quoted_tree, $tree_spec_name,
	@changed_sets, $set, $priority, $keywords, $description, $path);

    $| = 1;
    
    &verify_required_dirs ($CHECK);

    if ($specs_only == $SUBTREE_ONLY) {
	$specs_only = 0;
	$subtree_only = 1;
	$path = $sets[0];
    }

    $changedfile = new ChangedFile;

    # Clear the current contents of the changed file.
    $changedfile->reset_changed_file;

    print "Checking for extraneous files in specification dir.\n" if ($verbose);
    &display_extraneous_files ($config, $spec_dir, $verbose);

    print "Checking to see if specification dir has changed.\n" if ($verbose);
    print "$spec_dir\n" if ($verbose);
    if ($use_pgp) {
	&sigtree_verify ("$root_dir/$spec_spec");
    }
    &check_tree ($config, $TREE_ROOT, $spec_dir, '.', '', $changedfile, "$root_dir/$spec_spec");

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

    foreach $tree (@trees) {
	$tree_spec_name = &path_to_spec ($tree);
	if (!-e "$spec_dir/$tree_spec_name") {
	    print "\n" if ($verbose);
	    print "Warning: Specification for tree $tree doesn't exist. You need to initialize it. Skipping.\n";
	}
	elsif ($subtree_only || $config->tree_uses_sets ($tree, @sets)) {
	    print "\n$tree\n" if ($verbose && (!$specs_only || $use_pgp));

	    if ($use_pgp) {
		&sigtree_verify ("$spec_dir/$tree_spec_name");
	    }
	    if (!$specs_only) {
		&check_tree ($config, $TREE_ROOT, $tree, $path, '', $changedfile, "$spec_dir/$tree_spec_name");
		$changedfile->add_time ($tree);
	    }
	}
    }

    &show_change_details ($changedfile, $verbose, 1);
}

# Subroutine to show details of the changed file.  Used by check and changes -v.
# The verbose flag argument and the write flag argument are both used by check.
sub show_change_details {
    my ($changedfile, $verbose, $write_flag) = @_;
    my ($total_changes, $total_additions, $total_deletions, @changed_sets,
	$priority, $description,
	$changes, $additions, $deletions, @paths, $path, @attrs, $attr);

    ($total_changes, $total_additions, $total_deletions, @changed_sets) = $changedfile->get_sets;

    if ($total_changes == 0 && $total_additions == 0 && $total_deletions == 0) {
	print "\n" if ($verbose);
	print "No changes found.\n";
	$changedfile->delete_if_empty if ($write_flag);
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
		    $attr = shift (@attrs);
		    print "   $path ($attr)\n";
		}
	    }
	    if ($additions > 0) {
		print "Additions:\n";
		@paths = $changedfile->get_set_additions ($set);
		foreach $path (@paths) {
		    print "   $path\n";
		}
	    }
	    if ($deletions > 0) {
		print "Deletions:\n";
		@paths = $changedfile->get_set_deletions ($set);
		foreach $path (@paths) {
		    print "   $path\n";
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

    return if ($config->path_is_ignored ($tree, $path));

    if ($tree_root) {
	($spec, $fileattr) = new Spec ($tree, $spec_path);
	if ($verbose) {
	    ($host, $time, $user) = $spec->get_info;
	    $time = localtime ($time);
	    print "   Specification created $time on $host by $user.\n";
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

    ($description, $keywords, $priority) = $config->set_info ($primary_set);

    %differences = $fileattr->compare ($fileattr2, $keywords);

    if ($differences{'any'}) {
	$changedfile->add ($tree, $path, $primary_set, %differences);

	$fileattr->display_diffs ($primary_set, $priority, %differences) if ($verbose);
    }
    elsif ($differences{'mtimestasis'}) { # special case for where only change is a noticeable lack of change.
	$fileattr->display_diffs ($primary_set, $priority, %differences) if ($verbose);
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
            &check_tree ($config, $SUBTREE, $tree, $full_path, $spec, $changedfile);
	}
    }

    if ($fileattr2->{TYPE} eq 'dir') {
        foreach $file (@{$fileattr2->{FILES}}) {
	    $full_path = $file;
	    if (!$tree_root) {
	        $full_path = $path . '/' . $file;
            }
            &check_tree ($config, $SUBTREE, $tree, $full_path, $spec, $changedfile);
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

    &verify_required_dirs ($UPDATE);

    $changedfile = new ChangedFile;

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
	    # Need to remove the spec dir from the list.
	    $changedfile->delete($tree);
	    # Save changes (deletions).
	    $changedfile->store_changedfile;
	    # And delete the changed file if it's now empty.
	    $changedfile->delete_if_empty;
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

    $pgp_passphrase = &get_pgp_passphrase if ($use_pgp);

    # Ugly hack, but it prevents a problem.
    @changed_trees = $changedfile->get_trees if ($removed_old_trees);

    foreach $tree (@changed_trees) {
	$tree_spec_name = &path_to_spec ($tree);
	# Added $tree ne $spec_dir && so $spec_dir doesn't get treated as regular tree.
	# $spec_dir is initialized separately below.
	if ($tree ne $spec_dir && $config->tree_uses_sets ($tree, @sets)) {
	    if ($use_immutable) {
		&set_immutable_flag ($spec_dir_dir, $IMMUTABLE_OFF);
		&set_immutable_flag ($spec_dir, $IMMUTABLE_OFF);
		&set_immutable_flag ("$spec_dir/$tree_spec_name", $IMMUTABLE_OFF);
		if ($use_pgp) {
		    &set_immutable_flag ("$spec_dir/$tree_spec_name.sig", $IMMUTABLE_OFF);
		}
	    }
	    if ($verbose) {
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
		$fileattr->display_diffs ($primary_set, $priority, %differences) if ($verbose);
		if (!$differences{'any'}) {
		    print "Warning: There are no longer changes to path $full_path.\n";
		}
		elsif ($differences{'deleted'}) {
		    print "   Deleting $path.\n" if ($verbose);
		    $spec->delete ($tree, $changed_path);
		}
		else {
		    if ($differences{'added'} && $differences{'type'} eq 'nonexistent') {
			print "   No change made to spec for $path.\n" if ($verbose);
		    }
		    else {
			print "   Adding $path.\n" if ($verbose && $differences{'added'});
			print "   Updating $path.\n" if ($verbose && !$differences{'added'});
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
		&sigtree_sign ("$spec_dir/$tree_spec_name", $pgp_passphrase);
	    }
	    if ($use_immutable) {
		&set_immutable_flag ("$spec_dir/$tree_spec_name", $IMMUTABLE_ON);
		if ($use_pgp) {
		    &set_immutable_flag ("$spec_dir/$tree_spec_name.sig", $IMMUTABLE_ON);
		}
	    }
	}
    }
    if (-e $changed_file) {
	@changed_trees = $changedfile->get_trees;
	if ($verbose) {
	    print "There are still changed files in other sets to be updated.\n";
	    print "Trees remaining:\n";
	    print "@changed_trees\n";
	}
    }
    print "Updating specification for specification dir.\n" if ($verbose);
    if ($use_immutable) {
	&set_immutable_flag ("$root_dir/$spec_spec", $IMMUTABLE_OFF);
	if ($use_pgp) {
	    &set_immutable_flag ("$root_dir/$spec_spec.sig", $IMMUTABLE_OFF);
	}
    }
    # Update's the same as initialize in this respect.
    # This must be done before the specification for the specification dir
    # is created, since changing flags involves inode modification.
    if ($use_immutable) {
	&set_immutable_flag ($spec_dir, $IMMUTABLE_ON);
	&set_immutable_flag ($spec_dir_dir, $IMMUTABLE_ON);
    }
    &create_tree ($config, $TREE_ROOT, $spec_dir, '', '', "$root_dir/$spec_spec");
    if ($use_pgp) {
	&sigtree_sign ("$root_dir/$spec_spec", $pgp_passphrase);
    }
    if ($use_immutable) {
	&set_immutable_flag ("$root_dir/$spec_spec", $IMMUTABLE_ON);
	if ($use_pgp) {
	    &set_immutable_flag ("$root_dir/$spec_spec.sig", $IMMUTABLE_ON);
	}
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
# the current runlevel is too high.  It would be better to
# actually check, but perl's stat/lstat don't return the BSD
# file flags. [This is irrelevant, see &immutable_file sub!]
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
    elsif ($caller != $CHECK && !-w $root_dir) {
	die "Root dir is not writable. $root_dir\n";
    }

    if (!-e $spec_dir_dir) {
	if ($caller == $INITIALIZE) {
	    if (!mkdir ($spec_dir_dir, 0700)) {
		die "$! $spec_dir_dir\n";
	    }
	    else {
		print "Created main specification dir $spec_dir_dir.\n";
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
	    if ($use_immutable) {
		&set_immutable_flag ($spec_dir_dir, $IMMUTABLE_OFF);
	    }

	    if (!mkdir ($spec_dir, 0700)) {
		if ($use_immutable) {
		    &set_immutable_flag ($spec_dir_dir, $IMMUTABLE_ON);
		}
		die "$! $spec_dir\n";
	    }
	    else {
		if ($use_immutable) {
		    &set_immutable_flag ($spec_dir, $IMMUTABLE_ON);
		    &set_immutable_flag ($spec_dir_dir, $IMMUTABLE_ON);
		}
		print "Created host specification dir $spec_dir.\n";
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

    if (!-e $root_dir . "/$spec_spec") {
	die "Host specification does not exist. $root_dir/$spec_spec.\n"
	    if ($caller != $INITIALIZE);
    }
    elsif (!-r $root_dir . "/$spec_spec") {
	die "Host specification is not readable. $root_dir/$spec_spec.\n";
    }
    elsif ($caller != $CHECK && !-w $root_dir . "/$spec_spec") {
	die "Host specification is not writable. $root_dir/$spec_spec\n";
    }
    elsif ($caller != $CHECK && $use_immutable && $SECURELEVEL != 0 && ($immutable_flag ne $BSD_USER_IMMUTABLE_FLAG)) {
	die "Cannot write to existing host specification when kernel securelevel > 0.  Securelevel = $SECURELEVEL\n";
    }

    if ($use_pgp) {
	if (!-e $root_dir . "/$spec_spec.sig") {
	    die "Host specification signature does not exist. $root_dir/$HOSTNAME.sig.\n"
		if ($caller != $INITIALIZE);
	}
	elsif (!-r $root_dir . "/$spec_spec.sig") {
	    die "Host specification signature is not readable. $root_dir/$spec_spec.sig.\n";
	}
	elsif ($caller != $CHECK && !-w $root_dir . "/$spec_spec.sig") {
	    die "Host specification signature is not writable. $root_dir/$spec_spec.sig\n";
	}
    }
}

# Subroutine to display list of extraneous files in the specification dir.
sub display_extraneous_files {
    my ($config, $spec_dir, $verbose) = @_;
    my (@extraneous_files, $file);

    @extraneous_files = &_identify_extraneous_files ($config, $spec_dir);
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

    @extraneous_files = &_identify_extraneous_files ($config, $spec_dir);
    if ($#extraneous_files >= 0) {
	if ($use_immutable) {
	    &set_immutable_flag ($spec_dir_dir, $IMMUTABLE_OFF);
	    &set_immutable_flag ($spec_dir, $IMMUTABLE_OFF);
	}

	foreach $file (@extraneous_files) {
	    if ($use_immutable) {
		&set_immutable_flag ("$spec_dir/$file", $IMMUTABLE_OFF);
	    }
	    if (unlink ("$spec_dir/$file")) {
		print "$file removed.\n" if ($verbose);
	    }
	    else {
		print "Unable to remove $spec_dir/$file. $!\n";
	    }
	}
	if ($use_immutable) {
	    &set_immutable_flag ($spec_dir, $IMMUTABLE_ON);
	    &set_immutable_flag ($spec_dir_dir, $IMMUTABLE_ON);
	}
    }
    else {
	print "No extraneous files were found.\n" if ($verbose);
    }
}

# Subroutine to identify files in the specification dir that
# are not in the configuration.
sub _identify_extraneous_files {
    my ($config, $spec_dir) = @_;
    my (@files, $file, @trees, $tree, $tree_spec_name,
	$file_in_config, @extraneous_files);

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
		$tree_spec_name = &path_to_spec ($tree);
		$file_in_config = 1 if ($file eq $tree_spec_name ||
					$file eq "$tree_spec_name.sig");
	    } # trees (config) loop
	    push (@extraneous_files, $file) if (!$file_in_config);
	} # files (spec_dir) loop
	return (@extraneous_files);
    } # can read dir
    return ();
}

# Subroutine to determine if a file is writable.
sub writable_file {
    my ($file) = @_;
    my ($dir);

    if (-w $file && ($SECURELEVEL == 0 || !&immutable_file ($file))) {
	return 1;
    }
    # If file doesn't exist, dir must be writable.  We don't
    # auto-create dirs, so this isn't a recursive function.
    elsif (!-e $file) {
	$dir = File::Basename::dirname ($file);
	if (-w $dir && ($SECURELEVEL == 0 || !&immutable_file ($dir))) {
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
# Code borrowed from _get_file_flags in FileAttr method. [Perhaps
# in some earlier version, there's now little resemblance.]
sub immutable_file {
    my ($full_path) = @_;
    my ($escaped_full_path, $flags, $perms, $nlinks, $uid, $gid, $file);

    # Escape $ ( ) SP characters.
    $escaped_full_path = $full_path;
    #    $escaped_full_path =~ s/([\$\(\)\s])/\\$1/g;
    $escaped_full_path =~ s/(\$)/\\$1/g;

    if ((-e $CHFLAGS) && (-e "$full_path")) {
	$flags = `$LSFLAGS "$escaped_full_path"`;
	($flags, $file) = split (/\s+/, $flags);
	if ($flags =~ /$BSD_SYS_IMMUTABLE_FLAG/ || $flags =~ /$BSD_USER_IMMUTABLE_FLAG/) {
	    return 1;
	}
    }
    elsif ((-e $LSATTR) && (-e "$full_path")) {
	$flags = `$LSATTR "$full_path"`;
	($perms, $nlinks, $uid, $gid, $flags) = split (/\s+/, $flags);
	if ($flags =~ /i/) {
	    return 1;
	}
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
	    system "$CHFLAGS $flag $path";
	}
	elsif ($linux) {
	    system "$CHATTR $flag $path";
	}

	if (!$on && !&writable_file ($path)) {
	    print "Unable to reset immutable flag on $path.\n";
	    exit;
	}
    }
}

# Subroutine to get PGP passphrase.
sub get_pgp_passphrase {
    my ($pgp_passphrase, $current_tty, $temp_file);

    if ($PGP_or_GPG eq 'PGP' || $PGP_or_GPG eq 'GPG1' || $PGP_or_GPG eq 'signify') {
	system ("$STTY -echo");
	print "$PGP_or_GPG Passphrase: ";
	$pgp_passphrase = <STDIN>;
	print "\n";
	system ("$STTY echo");
	chop ($pgp_passphrase);
	return ($pgp_passphrase);
    }
    elsif ($PGP_or_GPG eq 'GPG') { # gpg-agent does the work when we sign something, so sign a temp file.
	$pgp_passphrase = '';
	$current_tty = `$TTY`;
	chop ($current_tty);
	$ENV{'GPG_TTY'} = $current_tty;
	$temp_file = `$MKTEMP -q /tmp/sigtree.XXXXXX`;
	chop ($temp_file);
	&sigtree_pgp_sign ($temp_file, $pgp_passphrase); # can skip the wrapper
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

    if ($use_signify) {
	&sigtree_signify_sign ($file, $pgp_passphrase);
    }
    else {
	&sigtree_pgp_sign ($file, $pgp_passphrase);
    }
}

# Generic wrapper for verification.
sub sigtree_verify {
    my ($file) = @_;

    if ($use_signify) {
	&sigtree_signify_verify ($file);
    }
    else {
	&sigtree_pgp_verify ($file);
    }
}

# Create a PGP signature in a detached file and save it.
sub sigtree_pgp_sign {
    my ($file, $pgp_passphrase) = @_;
    my ($signature, $version, @data, @errors);

    if (open (FILE, "<$file")) {
	while (<FILE>) {
	    push (@data, $_);
	}
	close (FILE);
    }
    else {
	print "Could not read $file to create $PGP_or_GPG signature.\n";
	return;
    }

    ($signature, $version) = pgp_sign ($config->{PGPKEYID}, $pgp_passphrase, @data);

    if (!defined ($signature)) {
	@errors = PGP::Sign::pgp_error;
	die "@errors";
    }

    if (open (FILE, ">$file.sig")) {
	print FILE "$signature\n";
	close (FILE);
    }
    else {
	print "Could not write $file to create $PGP_or_GPG signature.\n";
	return;
    }
}

# Verify a PGP signature.
sub sigtree_pgp_verify {
    my ($file) = @_;
    my ($signer, $signature, $version, @data, @errors);
    # $version is left undefined.

    if (open (FILE, "<$file")) {
	while (<FILE>) {
	    push (@data, $_);
	}
	close (FILE);
    }
    else {
	print "Cannot open file $file to verify $PGP_or_GPG signature.\n";
	return;
    }
    if (open (FILE, "<$file.sig")) {
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

    $signer = pgp_verify ($signature, $version, @data);
    if (!defined ($signer)) {
	@errors = PGP::Sign::pgp_error;
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

    if (!-r $file) {
	print "Could not read $file to create $PGP_or_GPG signature.\n";
	return;
    }

    if (!-w "$file.sig") {
	print "Could not write $file to create $PGP_or_GPG signature.\n";
	return;
    }

    if (!-r $signify_seckey) {
	print "Could not read secret key $signify_seckey to create $PGP_or_GPG signature.\n";
    }

    # Not great to have the passphrase on the command line.
    system ("$ECHO $signify_passphrase | $SIGNIFY -S -s $signify_seckey -m $file");
    if ($?) {
	# Something went wrong. At the moment stderr is not captured, so
	# it will be displayed.
	return;
    }
}

# Verify a signify signature on a specification.
sub sigtree_signify_verify {
    my ($file) = @_;
    my ($result);

    if (!-r $file) {
	print "Cannot open file $file to verify $PGP_or_GPG signature.\n";
	return;
    }

    if (!-r "$file.sig") {
	print "Cannot open file $file.sig to read $PGP_or_GPG signature.\n";
	return;
    }

    if (!-r $signify_pubkey) {
	print "Cannot open public key $signify_pubkey to verify $PGP_or_GPG signature.\n";
	return;
    }

    $result = `$SIGNIFY -V -p $signify_pubkey -m $file 2>/dev/null`;
    chop ($result);
    if ($?) {
	print "   Warning: Bad $PGP_or_GPG signature on specification. $file.sig\n";
    }
    elsif ($result eq 'Signature Verified') {
	print "   Good $PGP_or_GPG signature from $signify_pubkey on specification.\n" if ($verbose);
    }
    else {
	print "   Unexpected signature result on $file. $result\n";
    }
}

# Subroutine to convert pathname to a specification name by
# converting slashes to periods.
sub path_to_spec {
    my ($string) = @_;

    $string =~ s/^\///g;
    $string =~ s/\//./g;

    return ($string);
}


### Config package.

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

    bless $self, $class;

    $state = $GLOBAL_ATTRIBUTES;

    $line = 0;

    $current_set = 0;

    open (CONFIG, $config_file) ||
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
		${$self->{TREE_SETS}}{$path} = &_set_array_to_set_list (@sets);

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
		    $self->{TREE_DIR_EXCEPTION_SETS}->{$current_tree}->{$path} = &_set_array_to_set_list (@sets);
		}
		else {
		    $used_exception_paths{"$current_tree/$path"} = 1;
		    $self->{TREE_EXCEPTION_SETS}->{$current_tree}->{$path} = &_set_array_to_set_list (@sets);
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
	$tree_spec_name = &path_to_spec ($tree);
	if (!-e "$spec_dir/$tree_spec_name") {
	    &_add_set_to_tree ($tree, 'new');
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
    my ($path_set_list);

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

### FileAttr package.

# Methods to get information about an individual file, compare
# a file's attributes against an existing spec, etc.
package FileAttr;

# Method to create a new FileAttr record.
sub new {
    my $class = shift;
    my ($tree, $path, $sha_digest, $special) = @_;
    my ($sha_version, $sha_bits);
    my ($full_path, $link_target, $self, $ctx, $digest,
	$dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size,
	$atime, $mtime, $ctime, $blksize, $blocks, $flags);

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

    $self->{TYPE} = &_get_file_type ($full_path);

    if (-l $full_path) {
	$link_target = readlink ($full_path);
	$self->{LINK} = $link_target;

	# Need absolute path to be able to obtain other information about the
	# target.
	if (substr ($link_target, 0, 1) ne '/') {
	    $link_target = File::Basename::dirname ($full_path) . '/' . $link_target;
	}
	$self->{LINKTARGET_TYPE} = &_get_file_type ($link_target);

	$full_path = $link_target;
    }

    if (-e $full_path) {
	if (-f $full_path) {
	    if ($sha_digest =~ /-/) {
		($sha_version, $sha_bits) = split (/-/, $sha_digest);
		if (open (FILE, $full_path)) {
		    if ($sha_version == 2) {
			$ctx = Digest::SHA->new($sha_bits);
		    }
		    elsif ($sha_version == 3) {
			$ctx = Digest::SHA3->new($sha_bits);
		    }
		    else {
			die "Internal error: SHA version unknown. $sha_version";
		    }
		    $ctx->addfile(*FILE);
		    $digest = $ctx->hexdigest;
		    $self->{SHADIGEST} = $digest if (defined ($digest));
		    close (FILE);
		}
	    }
	    else {
		    $self->{SHADIGEST} = '<undefined>';
	    }
	}
	elsif (-d $full_path) {
	    if (opendir (DIR, $full_path)) {
		@{$self->{FILES}} = grep (!/^\.{1,2}$/, readdir (DIR));
		closedir (DIR);
	    }
	}

	($dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size,
	 $atime, $mtime, $ctime, $blksize, $blocks) = lstat $full_path;

	$self->{MODE} = $mode;
	$self->{NLINK} = $nlink;
	$self->{UID} = $uid;
	$self->{GID} = $gid;
	$self->{SIZE} = $size;
	$self->{MTIME} = $mtime;
	$self->{CTIME} = $ctime;

	$self->{FLAGS} = &_get_file_flags ($full_path);
    }

    bless $self, $class;
    return $self;
}

# Internal method to assign file type.
sub _get_file_type {
    my ($full_path) = @_;
    my ($type);

    # Check for link is done first, to avoid falsely identifying a link to
    # a nonexistent target as nonexistent rather than a link.
    if (-l $full_path) {
	$type = 'link';
    }
    elsif (!-e $full_path) {
	$type = 'nonexistent';
    }
    else {
	if (-p $full_path) {
	    $type = 'fifo';
	}
	elsif (-S $full_path) {
	    $type = 'socket';
	}
	elsif (-b $full_path) {
	    $type = 'block device';
	}
	elsif (-c $full_path) {
	    $type = 'char device';
	}
	elsif (-f $full_path) {
	    $type = 'file';
	}
	elsif (-d $full_path) {
	    $type = 'dir';
	}
	else {
	    $type = '<undefined>';
	}
    }

    return ($type);
}

# Internal method to obtain file flags.  This is icky, I'd like to get them
# from lstat.
sub _get_file_flags {
    my ($full_path) = @_;
    my ($escaped_full_path, $flags, $perms, $nlinks, $uid, $gid);

    # Escape $ ( ) SP characters.
    $escaped_full_path = $full_path;
    #    $escaped_full_path =~ s/([\$\(\)\s])/\\$1/g;
    $escaped_full_path =~ s/(\$)/\\$1/g;   
    
    if (-e $CHFLAGS) {
	if (-e "$full_path") {
	    $flags = `$LSFLAGS "$escaped_full_path"`;
	    if (defined ($flags) && (length ($flags) > 0)) {
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
	$flags = `$LSATTR $full_path`;
	if (defined ($flags)) {
	    ($flags, $file) = split (/\s+/, $flags);
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
package Spec;

use Storable;

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
	$self = retrieve ($spec_path);
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

    store ($self, $spec_path);
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
package ChangedFile;

use Storable;

# Method to create a new changed file or read in its contents,
# and reset counters for check.
sub new {
    my $class = shift;
    my ($self);

    if (-e $changed_file) {
	$self = retrieve ($changed_file);
    }
    else {
	$self = ();

	$self->{CHANGES} = ();
	$self->{ADDITIONS} = ();
	$self->{DELETIONS} = (); 
	$self->{SET_TO_PATH} = (); 
	$self->{SET_TO_PATH_ADD} = (); 
	$self->{SET_TO_PATH_DEL} = (); 
	$self->{SET_TO_PATH_CHANGE} = (); 
	$self->{SET_TO_PATH_CH_ATTR} = (); 
    }

    bless $self, $class;
    return $self;
}

# Method to reset the changed file in preparation for recreating it.
sub reset_changed_file {
    my $self = shift;
    my $class = ref ($self) || $self;

    $self->{CHANGES} = ();
    $self->{ADDITIONS} = ();
    $self->{DELETIONS} = (); 
    $self->{SET_TO_PATH} = (); 
    $self->{SET_TO_PATH_ADD} = (); 
    $self->{SET_TO_PATH_DEL} = (); 
    $self->{SET_TO_PATH_CHANGE} = (); 
    $self->{SET_TO_PATH_CH_ATTR} = (); 
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

# Method to return array of changed sets, ordered from highest
# to lowest priority, along with total number of changes, additions,
# and deletions found in this check.
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
    if ($#trees == -1) {
	unlink ($changed_file);
    }
}

# Method to store changed file.
sub store_changedfile {
    my $self = shift;
    my $class = ref ($self) || $self;

    store ($self, $changed_file);
}

1;

### End ChangedFile package.
