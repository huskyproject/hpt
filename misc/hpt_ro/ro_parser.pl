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

my @acl = Hpt_ro::readroconf($Hpt_ro::ro_conf);
my @echoes = Hpt_ro::readhptconf($Hpt_ro::hptconf);

my $curtime = time;

my $denyonly = (@ARGV && lc($ARGV[0]) eq 'denyonly') ? 1 : 0;

# print expired rules if they exist
{
  my @exrules;
  {
    my ($d,$m,$y) = (localtime())[3..5];
    my $curtime = sprintf("%02d%02d%02d",$y % 100, $m + 1, $d);

    foreach(@acl) {
      next unless $_->{date};
      if ($_->{date} lt $curtime) {
        push @exrules,$_->{cfgline};
        $_ = undef;
      }
    }
  }
  if (@exrules) {
    print "== Expired rules ==\n\n";
    print "$_\n" foreach(@exrules);
    print "\n";
  }
}

print "== Echoes ==\n\n";

foreach(@echoes) {
  my $echo = $_;
  my $echotag = $echo->{echotag};
  my $echogroup = $echo->{group} ? $echo->{group} : "";
  my @links;
  my $header = $echotag . ($echogroup ? " -g $echogroup" : "") . "\nLinks:\n";
  $echogroup = "-" . $echogroup if $echogroup;

  # temporary @acl (exclude rules no matched with echotag)
  my @tacl = @acl;

FORLINKS:
  foreach(@{$echo->{links}}) {
    my $link = $_;
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

      push @links,"$link, " . ($acl->{deny} ? "deny" : "allow") . " - $acl->{cfgline}" if $acl->{deny} || ! $denyonly;
      next FORLINKS;

    } # foreach(@tacl)
    push @links,"$link, deny - no rule matched";
  } # foreach(@{$echo->{links}})
  if (@links) {
    print $header;
    print "  $_\n" foreach(@links);
    print "\n";
  }
}
