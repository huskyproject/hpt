#
# HPT Advanced Readonly
# v 0.1
#
# Copyright (c) 2002 Andrew Sagulin. Freeware.
#
# $Id$

use strict;

my $workdir;
BEGIN { 
  my $wd;
  if ($^O = 'MSWin32') { ($wd = $0) =~ s/[^\\]+$//;}
  else {($wd = $0) =~ s/[^\/]+$//;}
  $workdir = $wd ? $wd : ".";
}

use lib ($workdir);
use Hpt_ro;

my $cfg = $Hpt_ro::ro_conf;
my $cfgtmp = $cfg . ".tmp";
my $cfgbak = $cfg . ".bak";

open(IN,$cfg) or die "Can not open $cfg: $!";
open(OUT,">$cfgtmp")  or die "Can not create $cfgtmp: $!";

my ($d,$m,$y) = (localtime())[3..5];
my $curtime = sprintf("%02d%02d%02d",$y % 100, $m + 1, $d);

while(<IN>) {
  chomp;
  my $line = $_; # save orig line
  tr/\t/ /;
  $_ = Hpt_ro::trim($_);
  if (/ *(?:allow|deny)(?: +[^ ]+){2} +(\d\d)\.(\d\d)\.(\d\d)/i) {
    next if sprintf("%02d%02d%02d",$3,$2,$1) lt $curtime;
  }
  print OUT "$line\n";
}

close(IN);
close(OUT);

rename($cfg,$cfgbak);
rename($cfgtmp,$cfg);
