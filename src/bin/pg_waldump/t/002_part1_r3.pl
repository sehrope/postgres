# Repeat run of 002_part1.pl for another timing sample.
use strict;
use warnings FATAL => 'all';
use FindBin;
exec $^X, (map { '-I' . $_ } grep { !ref } @INC),
  "$FindBin::RealBin/002_part1.pl"
  or die "exec failed: $!";
