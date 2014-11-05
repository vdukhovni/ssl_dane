# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Danessl.t'

#########################

# change 'tests => 2' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 2;
BEGIN { use_ok('Danessl') };


my $fail = 0;
foreach my $constname (qw(
	SSL_DANE_SELECTOR_CERT SSL_DANE_SELECTOR_LAST SSL_DANE_SELECTOR_SPKI
	SSL_DANE_USAGE_FIXED_LEAF SSL_DANE_USAGE_LAST
	SSL_DANE_USAGE_LIMIT_ISSUER SSL_DANE_USAGE_LIMIT_LEAF
	SSL_DANE_USAGE_TRUSTED_CA)) {
  next if (eval "my \$a = $constname; 1");
  if ($@ =~ /^Your vendor has not defined Danessl macro $constname/) {
    print "# pass: $@";
  } else {
    print "# fail: $@";
    $fail = 1;
  }

}

ok( $fail == 0 , 'Constants' );
#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

