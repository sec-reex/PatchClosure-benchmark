# Environment-only install stub (NOT Majordomo application code).
# Majordomo 2's postinstall step (setup/setup_func.pl mta_append) does
#   require "setup/mta_$config->{mta}.pl"
# and calls setup_<mta> / setup_<mta>_domain to write MTA alias files. The
# upstream tarball ships mta_{sendmail,exim,qmail,postfix}.pl but NO
# mta_none.pl, so with mta=none the postinstall aborts before completing.
# This benchmark needs no mail delivery (the exploit is the read-only web
# `help` command), so we drop in a no-op mta_none.pl to let `make install`
# finish cleanly. It does not alter the vulnerable code path.
sub setup_none        { 1 }
sub setup_none_domain { 1 }
1;
