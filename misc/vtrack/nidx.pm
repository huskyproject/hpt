{
package nidx;

use strict;
use DB_File;
use Exporter;

our $VERSION = "0.05";
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(ncheck hub region nodeline);

my ($db, %h, $nodelistDir);
my ($w_log, $soft_zone, $soft_net, %ok_zone) = (0, 0, 0);
sub idx_name () { return "vtrack.idx"; }
# init($nodelistDir, nodelistHash, \%options)
sub init {
  $nodelistDir = $_[0] if defined $_[0];
  $main::{$_[1]} = \%h if defined $_[1];
  $w_log     = $_[2]{w_log}     if defined $_[2]{w_log};
  $soft_zone = $_[2]{soft_zone} if defined $_[2]{soft_zone};
  $soft_net  = $_[2]{soft_net}  if defined $_[2]{soft_net};
  if (defined $_[2]{ok_zone} && @{$_[2]{ok_zone}}) {
    %ok_zone = ();
    for my $z (@{$_[2]{ok_zone}}) { $ok_zone{$z} = 1; }
  }
  return 0 unless defined $nodelistDir;
  $db = tie %h, "DB_File", $nodelistDir."/".idx_name, O_CREAT|O_RDWR, 0644, $DB_BTREE;
}
# done([$unlink])
sub done {
  untie %h;
  if ($_[0] && defined $db) { unlink $nodelistDir."/".idx_name; }
}
# update(@nodemasks)
sub update {
  my $need = 0;
  my @files = ();
  for (my $i = 0; $i < @_; $i++) {
    my ($mask, $z, $reg) = split /[;:]/, $_[$i];

    my $max = 0; my $cur;
    opendir(F, $nodelistDir) || return undef;
    while (my $name = readdir(F)) {
      next unless $name =~ /^$mask$/i;
      my $cft = (stat "$nodelistDir/$name")[9];
      if ($cft > $max) { $max = $cft; $cur = $name; }
    }
    closedir(F);

    my ($nname, $ntime) = split /;/, $h{"#$i"};
    $need = 1 if ($nname ne "$nodelistDir/$cur" || $ntime < $max);
    push @files, "$nodelistDir/$cur;$z;$reg;$max";
  }
  compile(@files) if $need;
}
# compile(@nodelists)
sub compile {
my ($z, $n, $f, $reg, $hub, $nlno);
  done(1); init();
  $nlno = 0;
  for (my $i = 0; $i < @_; $i++) {
    my ($name, $z, $reg, $ts) = split /;/, $_[$i];
    open F, $name or next; binmode F;
    eval { ::w_log("nidx::compile(): compiling $name"); } if $w_log;
    $h{"#$nlno"} = "$name;$ts";
    while (<F>) {
      next if /^\s*;/;
      if (/^Zone,(\d+)/o) { $z = $1; $reg = $n = $z; $f = $hub = 0; }
      elsif (/^Region,(\d+)/o) { $reg = $n = $1; $f = $hub = 0; }
      elsif (/^Host,(\d+)/o) { $n = $1; $f = $hub = 0; }
      elsif (/^Hub,(\d+)/o) { $f = $hub = $1; }
      else { ($f) = /^[^,]*,(\d+)/o; }
      $h{"$z:$n/$f"} = "$nlno:$reg:$hub:".(tell(F)-length $_);
    }
    close F;
    $nlno++;
  }
}
# nodelists()
sub nodelists () {
  my @arr = (); my $i = 0;
  while (my $s = $h{'#'.$i++}) { 
    push @arr, $s =~ /([^\/\\]+);\d+$/o;
  }
  return @arr;
}
# ncheck($addr)
sub ncheck {
  (my $node = $_[0]) =~ s![.@].*$!!o;
  return 1 if $h{$node};
  my ($zone, $net) = $node =~ /^(\d+):(\d+)/;
  return 1 if ($soft_net && !defined $h{"$zone:$net/0"} && defined $h{"$zone:$zone/0"});
  return 1 if ($soft_zone && !defined $h{"$zone:$net/0"} && !defined $h{"$zone:$zone/0"});
  return 1 if (!defined $h{"$zone:$net/0"} && !defined $h{"$zone:$zone/0"} && defined $ok_zone{$zone});
  return undef;
}
# hub($addr)
sub hub {
  (my $node = $_[0]) =~ s!\.\d+$!!o;
  my $s;
  unless ($s = $h{$node}) { $node =~ s!/\d+!/0!; return $h{$node} ? $node : undef }
  my ($hub) = $s =~ /^\d+:\d+:(\d+):/o;
  $node =~ s!([^/]+).*!$1/$hub!o;
  return $node;
}
# region($addr)
sub region {
  (my $node = $_[0]) =~ s!\.\d+$!!o;
  my $s;
  unless ($s = $h{$node}) { $node =~ s!/\d+!/0!; }
  return undef unless ($s = $h{$node});
  my ($reg) = $s =~ /^\d+:(\d+):/o;
  $node =~ s!([^:]+).*!$1:$reg!o;
  return $node;
}
# nodeline($addr)
sub nodeline {
  (my $node = $_[0]) =~ s!\.\d+$!!o;
  return undef unless (my $s = $h{$node});
  my ($nlno, $nlpos) = $s =~ /^(\d+):\d+:\d+:(\d+)/o;
  return undef unless ($s = $h{"#$nlno"});
  $s =~ s/;.*$//o;
  open F, $s;
  seek F, $nlpos, 0;
  $s = <F>; chomp $s;
  close F;
  return $s;
}

}

1;

__END__

nidx::init("c:/fido/nodelist", nidx, {soft_net=>1, ok_zone=>[1..6]});
nidx::update('nodelist\.\d{3}', 'net_463\.\d{3}:2:46');
for $addr ( ('2:463/59', '2:5020/487', '2:5020/488', '2:550/180', '3:123/987') ) {
  print "$addr: ";
  if ($nidx{$addr}) {
    print "hub=".nidx::hub($addr)."; region=".nidx::region($addr);
    print "; line:\n".nidx::nodeline($addr)."\n";
  } else { print "not found; ncheck=".nidx::ncheck($addr)."\n"; }
}
nidx::done;
