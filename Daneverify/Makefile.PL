#! /usr/bin/perl
use 5.012005;
use Config;

use ExtUtils::MakeMaker;

my $DANESSLDIR = "/Volumes/pgit/ssl_dane";

# push(@INC, "..");

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Daneverify',
    VERSION_FROM      => 'lib/Daneverify.pm',
    ABSTRACT_FROM     => 'lib/Daneverify.pm',
    AUTHOR            => 'Viktor Dukhovni <postfix-users@dukhovni.org>',
    LIBS              => [ "-L.. -ldanessl -lssl -lcrypto" ],
    INC               => "-I..",
);
