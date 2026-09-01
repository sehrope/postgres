# Repeat run of 003_part2.pl for another timing sample.
use strict;
use warnings FATAL => 'all';
use FindBin;
exec $^X, (map { '-I' . $_ } grep { !ref } @INC),
  "$FindBin::RealBin/003_part2.pl"
  or die "exec failed: $!";
