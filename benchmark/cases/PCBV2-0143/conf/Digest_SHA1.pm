package Digest::SHA1;
# Environment-only compatibility shim (NOT Majordomo application code).
# Debian bullseye dropped libdigest-sha1-perl; Majordomo 2 (2011) requires
# Digest::SHA1. This thin wrapper delegates to the core Digest::SHA module,
# providing the same functional + OO API Majordomo uses (sha1_hex,
# sha1_base64, and `new Digest::SHA1` -> add/hexdigest/...). It does not touch
# the vulnerable code path (lib/Majordomo.pm _list_file_get) in any way.
use strict; use warnings;
use Digest::SHA ();
use Exporter qw(import);
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(sha1 sha1_hex sha1_base64);
our $VERSION = "2.13";
sub sha1        { Digest::SHA::sha1(@_) }
sub sha1_hex    { Digest::SHA::sha1_hex(@_) }
sub sha1_base64 { Digest::SHA::sha1_base64(@_) }
sub new         { my $c = shift; return Digest::SHA->new(1); }
1;
