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
  $workdir = $wd;
}

use lib ($workdir);
use Hpt_ro;

my @acl = Hpt_ro::readroconf($Hpt_ro::ro_conf);
my @echoes = Hpt_ro::readhptconf($Hpt_ro::hptconf);

#Hpt_ro::getdata(\@acl,\@echoes);

my $curtime = time;

print "Expired rules:\n";
{
  my ($d,$m,$y) = (localtime())[3..5];
  my $curtime = sprintf("%02d%02d%02d",$y % 100, $m + 1, $d);

  foreach(@acl) {
    next unless $_->{date};
    if ($_->{date} lt $curtime) {
      print "  $_->{cfgline}\n";
      $_ =undef;
    }
  }
}

print "\nEchoes:\n\n";

foreach(@echoes) {
  my $echo = $_;
  my $echotag = $echo->{echotag};
  my $echogroup = $echo->{group} ? $echo->{group} : "";
  print "$echotag";
  print $echogroup ? " -g $echogroup\n" : "\n";
  $echogroup = "-" . $echogroup if $echogroup;
  print "Links:\n";

  # temporary @acl (exclude rules no matched with echotag)
  my @tacl = @acl;

FORLINKS:
  foreach(@{$echo->{links}}) {
    my $link = $_;
    print "  $link, ";
FORACL:
    foreach(@tacl) {
      my $acl = $_;
      next unless $acl;
      my $matched = 0;
      foreach(@{$acl->{echogroup}}) {
        my $group = $_;
        if ($group =~ /^-/) {
          next unless $echogroup;
          if ($echogroup eq $group) {$matched = 1; last;}
        }
        else {
          if ($echotag =~ /$group/) {$matched = 1; last;}
        }
      }
      unless ($matched) {
        $_ = undef; # exclude by echotag
        next FORACL;
      }

      $matched = 0;
      foreach(@{$acl->{linkgroup}}) {
        if ($link =~ /$_/) {$matched = 1; last;}
      }
      next FORACL unless $matched;

      print $acl->{deny} ? "deny" : "allow", " - $acl->{cfgline}\n";
      next FORLINKS;

    }
    print "deny - no rule matched\n";
  }
  print "\n";
}
