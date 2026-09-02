
# Copyright (c) 2024-2026, PostgreSQL Global Development Group

# Test the incremental (table-driven) json parser.


use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Utils;
use Test::More;
use FindBin;

my $test_file = "$FindBin::RealBin/../tiny.json";

my @exes = (
	[ "test_json_parser_incremental", ],
	[ "test_json_parser_incremental", "-o", ],
	[ "test_json_parser_incremental_shlib", ],
	[ "test_json_parser_incremental_shlib", "-o", ]);

foreach my $exe (@exes)
{
	note "testing executable @$exe";

	# Test the  usage error
	my ($stdout, $stderr) = run_command([ @$exe, "-c", 10 ]);
	like($stderr, qr/Usage:/, 'error message if not enough arguments');

	# Test that we get success for small chunk sizes from 64 down to 1.
	# The -r mode runs all of them in one process, with the output of each
	# run followed by a null byte.
	($stdout, $stderr) = run_command([ @$exe, "-r", 64, $test_file ]);

	my @stdout = unpack("(Z*)*", $stdout);
	my @stderr = unpack("(Z*)*", $stderr);

	is(scalar @stdout, 64, "stdout has correct number of entries");
	is(scalar @stderr, 64, "stderr has correct number of entries");

	my $i = 0;

	for (my $size = 64; $size > 0; $size--)
	{
		like($stdout[$i], qr/SUCCESS/, "chunk size $size: test succeeds");
		is($stderr[$i], "", "chunk size $size: no error output");
		$i++;
	}
}

done_testing();
