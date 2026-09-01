# Copyright (c) 2022-2026, PostgreSQL Global Development Group

pg_waldump_sources = files(
  'archive_waldump.c',
  'compat.c',
  'pg_waldump.c',
  'rmgrdesc.c',
)

pg_waldump_sources += rmgr_desc_sources
pg_waldump_sources += xlogreader_sources
pg_waldump_sources += files('../../backend/access/transam/xlogstats.c')

if host_system == 'windows'
  pg_waldump_sources += rc_bin_gen.process(win32ver_rc, extra_args: [
    '--NAME', 'pg_waldump',
    '--FILEDESC', 'pg_waldump - decode and display WA'])
endif

pg_waldump = executable('pg_waldump',
  pg_waldump_sources,
  dependencies: [frontend_code, libpq, lz4, zstd],
  c_args: ['-DFRONTEND'], # needed for xlogreader et al
  kwargs: default_bin_args,
)
bin_targets += pg_waldump

tests += {
  'name': 'pg_waldump',
  'sd': meson.current_source_dir(),
  'bd': meson.current_build_dir(),
  'tap': {
    'env': {'TAR': tar.found() ? tar.full_path() : ''},
    'tests': [
      't/001_basic.pl',
      't/002_save_fullpage.pl',
      't/001_v2min.pl',
      't/001_v2min_r1.pl',
      't/001_v2min_r2.pl',
      't/001_v2min_r3.pl',
      't/001_v2min_r4.pl',
      't/002_part1.pl',
      't/002_part1_r1.pl',
      't/002_part1_r2.pl',
      't/002_part1_r3.pl',
      't/002_part1_r4.pl',
      't/003_part2.pl',
      't/003_part2_r1.pl',
      't/003_part2_r2.pl',
      't/003_part2_r3.pl',
      't/003_part2_r4.pl',
      't/004_part3.pl',
      't/004_part3_r1.pl',
      't/004_part3_r2.pl',
      't/004_part3_r3.pl',
      't/004_part3_r4.pl',
    ],
  },
}

subdir('po', if_found: libintl)
