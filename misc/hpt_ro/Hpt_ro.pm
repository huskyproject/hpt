#
# HPT Advanced Readonly
# v 0.1
#
# Copyright (c) 2002 Andrew Sagulin. Freeware.
#
# $Id$

package Hpt_ro;

use strict;
use vars qw($ro_conf $hptconf);
use 5.006;

my $groupsymbol = '@';
my $commentchar = '#';

#
# put your paths here
#
my $defhptconf = "n:\\bin\\hpt\\config";
$ro_conf = "n:\\bin\\hpt\\ro.cfg";

$hptconf = $ENV{FIDOCONFIG} ? $ENV{FIDOCONFIG} : $defhptconf;

my (%allow,%deny);

1;

#
# protos
#
sub trim($);
sub echo2re($);
sub link2re($);
sub readhptconf($);
sub readroconf($);

#
# init %allow and %deny
#

sub init() {

  my @acl = readroconf($ro_conf);
  my @echoes = readhptconf($hptconf);

  {
    my ($d,$m,$y) = (localtime())[3..5];
    my $curtime = sprintf("%02d%02d%02d",$y % 100, $m + 1, $d);

    # Expired rules
    foreach(@acl) {
      next unless $_->{date};
      $_ = undef if ($_->{date} lt $curtime);
    }
  }

  foreach(@echoes) {
    my $echo = $_;
    my $echotag = $echo->{echotag};
    my $echogroup = $echo->{group} ? "-" . $echo->{group} : "";
  
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
  
        if ($acl->{deny}) {$deny{$echotag}{$link} = $acl->{cfgline};} 
        else {$allow{$echotag}{$link} = 1;}

        next FORLINKS;
      } # foreach(@tacl)
  
      $deny{$echotag}{$link} = "no rule"; # deny - no rules matched
  
    } # foreach(@{$echo->{links}})
  } # foreach(@echoes)
} # init()

#
# check link for readonly
#
# return reason if access denied
#

sub checkro($$) {
  my($echotag,$link) = @_;
  return "" unless $echotag; # netmail? -> return
  $link .= ".0" unless $link =~ /\.\d+$/;
  $echotag = uc($echotag);
  return $deny{$echotag}{$link} if exists $deny{$echotag}{$link};
  return "" if exists $allow{$echotag}{$link};
  init(); # reread configs
  return $deny{$echotag}{$link} if exists $deny{$echotag}{$link};
  # Echo or link not exist in spite of rereading config 
  # so it's not my business - let tosser do its job
  return ""
}

#
# delete trailing and leading spaces
#
# Usage: $b = trim($a); 
#
sub trim($) {
  my $s=shift @_;
  $s =~ s/^[ \t]+//; 
  $s =~ s/[ \t]+$//;
  return $s;
}

#
# convert echo mask to regular expression
#
sub echo2re($) {
  my $re = shift @_;
  $re = uc(quotemeta($re));
  $re =~ s/\\\*/.*/g;
  return qr/^$re$/;
}

#
# convert link mask to regular expression
#
sub link2re($) {
  my $re = shift @_;
  $re .= ".0" unless $re =~ /\..+$/; # add 0-point to node address
  $re = quotemeta($re);
  $re =~ s/\\\*/\\d+/g;
  return qr/^$re$/;
}

#
# recursive function for reading HPT config
#
sub readhptconf($) {
  my $cfgname = shift @_;
  my @echoes;
  open(my $hcfg,$cfgname) or die "Can not open $cfgname: $!\n";
  while(<$hcfg>) {
    chomp;
    s/([^$commentchar]*)$commentchar.+/$1/; # kill comments
    tr/\t/ /;
    $_ = trim($_);
    next if /^$/; # skip empty lines

    if (/^include +([^ ]+)/i) {
      push @echoes, readhptconf($1);
    }
    elsif (/^echoarea\b/i) {
      my $echo;
      # remove some options at first. They (may) contain address-like words
      s/-d +"[^"]+"//i; # description
      s/-a +\d+:\d+\/\d+(\.\d+)?//i; # our AKA
      s/-sbadd\([^)]+\)//i; # sbadd
      s/-sbign\([^)]+\)//i; # sbign
      my(undef,$echotag,undef,@options) = split / +/;
      $echotag = uc($echotag);
      $echo->{echotag} = $echotag;
      $echo->{group} = $1 if /-g +([^ ]+)/;
      while(@options) {
        my $opt = shift @options;
        if ($opt =~ /\d+:\d+\/\d+(\.\d+)?/) { # opt is a link
          $opt .= '.0' unless $opt =~/\.\d+$/; 
          push @{$echo->{links}},$opt;
        }
      } # while(@options)
      push @echoes,$echo;
    } # elsif (/^echoarea\b/i)
  } # while(<$hcfg>)
  close($hcfg);
  return @echoes;
}

#
# read hpt_ro config
#
sub readroconf($) {
  my $cfgname = shift @_;
  my %echogroups;
  my %linkgroups;
  my @acl;
  open(my $hcfg,$cfgname) or die "Can not open $cfgname: $!\n";
  
  my $state = 'main'; # main, echo, link
  my $curgroup;
  
  while(<$hcfg>) {
    chomp;
    s/([^$commentchar]*)$commentchar.+/$1/; # kill comments
    tr/\t/ /;
    $_ = trim($_);
    next if /^$/;
  
    if ($state eq 'main') {
  
      if (/^echogroup\b/i) {
        my(undef,$groupname,@items) = split / +/;
        die "Echogroup name can not start from '-'" if $groupname =~ /^-/;
        if (@items) {
          $_ = echo2re($_) foreach(@items);
          push @{$echogroups{$groupname}},@items;
        }
        else {
          $curgroup = $groupname;
          $state = 'echo';
        }
        next;
      } # echogroup
  
      if (/^linkgroup\b/i) {
        my(undef,$groupname,@items) = split / +/;
        if (@items) {
          $_ = link2re($_) foreach(@items);
          push @{$linkgroups{$groupname}},@items;
        }
        else {
          $curgroup = $groupname;
          $state = 'link';
        }
        next;
      } # linkgroup
   
      if (/^(allow|deny)\b/i) {
        my(undef,$link,$echo,$date) = split / +/;
  
        my %acl;
        $acl{deny} = /^deny/i ? 1 : 0;
        $acl{cfgline} = $_;
        if ($link =~ /^$groupsymbol/) { 
          $link =~ s/^@//;
          die "Unknown group '$link' at '$_'\n" unless $linkgroups{$link};
          $acl{linkgroup} = $linkgroups{$link};
        }
        elsif (/^-/) {
          $acl{linkgroup} = [link2re($link)];
        }
        else {
          $acl{linkgroup} = [link2re($link)];
        }
        if ($echo =~ /^$groupsymbol/) { 
          $echo =~ s/^@//;
          if ($echo =~ /^-/) {
            $acl{echogroup} = [$echo];
          }
          else {
            die "Unknown group '$echo' at '$_'\n" unless $echogroups{$echo};
            $acl{echogroup} = $echogroups{$echo};
          }
        }
        else {
          $acl{echogroup} = [echo2re($echo)];
        }
        if ($date) {
          $date =~ /(\d\d)\.(\d\d)\.(\d\d)/ or die "Bad date '$date' at '$_'\n";
          $acl{date} = sprintf("%02d%02d%02d",$3,$2,$1)
        }
        push @acl,\%acl;
        next;
      } # allow | deny
  
    } # main state
    elsif ($state eq 'echo') {
      if (/^endechogroup$/i) {
        $state = 'main';
        next;
      }
      my @items = split / +/;
      $_ = echo2re($_) foreach(@items);
      push @{$echogroups{$curgroup}},@items;
    } # echo state
    elsif ($state eq 'link') {
      if (/^endlinkgroup$/i) {
        $state = 'main';
        next;
      }
      my @items = split / +/;
      $_ = link2re($_) foreach(@items);
      push @{$linkgroups{$curgroup}},@items;
    } # link state
    else {die "Unknown parser state: $state\n";}
  } # while 

  die "'echogroup' $curgroup block not closed by 'endechogroup'" if $state eq 'echo';
  die "'linkgroup' $curgroup block not closed by 'endlinkgroup'" if $state eq 'link';
  close($hcfg);

  return @acl;
}

