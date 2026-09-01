# Repeat run of 001_v2min.pl for another timing sample.
use strict;
use warnings FATAL => 'all';
use FindBin;
exec $^X, (map { '-I' . $_ } grep { !ref } @INC),
  "$FindBin::RealBin/001_v2min.pl"
  or die "exec failed: $!";
