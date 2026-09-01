# Repeat run of 004_part3.pl for another timing sample.
use strict;
use warnings FATAL => 'all';
use FindBin;
exec $^X, (map { '-I' . $_ } grep { !ref } @INC),
  "$FindBin::RealBin/004_part3.pl"
  or die "exec failed: $!";
