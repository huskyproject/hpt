#!/usr/bin/perl
# hptstat (c)opyright 2002-03, by val khokhlov
$ver="0.8";
%areas;                       # areas found in stat (tag=>id), id=1,2,3,...
@area_tag;                    # ...reverse array (id=>tag)
%links;                       # links found in stat
@stat;                        # array ($tag, @addr, @msgs, @bytes)
                              # idx: 0  1 2 3 4 5  6   7    8   9   10
                              # val: id z:n/f.p in out dupe bad inb outb
$INB = $OUTB = 0;             # total input and output bytes
%config_areas, @config_links; # parsed hpt config

# ====================================================================
# MODIFY THE SECTION BELOW TO CUSTOMIZE REPORT
# -->---

# init(<default binary stat log>[, <default config file>])
init("/home/val/fido/log/hpt.sta", "/home/val/fido/hpt/hpt.conf");
# header
print center("hpt statistics"),
      center(localtime($stat1)." - ".localtime($stat2)), "\n";
# top 10 areas graph
print center("Top 10 areas"),
      join("\n", make_histgr('Area', 1, [9,10], [9,10], 10, 2)), "\n\n";
# links graph
print center("Traffic by links"),
      join("\n", make_histgr('Link', 0, [9,10], [9,10])), "\n\n";
# areas summary
print center("Areas summary"), "\n",
      join("\n", make_summary('Area', 0, 1)), "\n\n";
# links summary
print center("Links summary"), "\n",
      join("\n", make_summary('Link', 0, 1)), "\n\n";
# zero traffic areas
print center("Zero traffic areas"), "\n",
      join("\n", make_notraf()), "\n\n";
# bad and dupe combined report
print center("Bad and duplicate messages"), "\n",
      join("\n", make_baddupe(['Dupe', ' Bad'], 2, [7,8], [7,8])), "\n\n";

# --<---
# END OF CUSTOMIZATION SECTION
# ====================================================================

# --------------------------------------------------------------------
# center a line
sub center { return sprintf '%'.(39-length($_[0])/2)."s%s\n", ' ', $_[0]; }
# --------------------------------------------------------------------
# parse stat file into @stat
sub parse_stat {
  my $gz;
  my ($name, $warn) = @_;
  print STDERR " * processing ".($GZ ? "gzip'ed " : "")."stat file: $name\n" if $DBG;
eval {
  open F, $name or die "Can't open stat file $name\n"; binmode F;
  if (!$GZ && $name !~ /\.[Gg][Zz]$/o) { read F, $_, 16; }
  else {
    die "Compress::Zlib perl module required for gzip'ed files processing\n" unless eval { require Compress::Zlib; import Compress::Zlib; 1; };
    $gz = gzopen(\*F, "r") or die "gzopen() error: $gzerrno\n";
    $gz->gzread($_, 16);
  }
  my ($rev, $t0) = unpack 'x2 S1 L1', $_;
  # check revision
  if ($rev != 1) {
    $gz->gzclose if $gz;
    close F;
    die "Stat file $name revision $rev, expected 1\n";
  }
  # set times
  $stat1 = $t0 if !defined $stat1 || $stat1 > $t0;
  $stat2 = (stat F)[9] if $stat2 < (stat F)[9];
  # read file
  while ( $gz ? $gz->gzread($_, 4) > 0 : !eof F ) {
    read F, $_, 4 unless $gz;
    my ($lc, $tl, $tag, $id) = unpack 'S2', $_;
    # area tag
    !$gz ? read F, $tag, $tl : $gz->gzread($tag, $tl);
    $id = $areas{$tag};
    if (!defined $id) { $areas{$tag} = $id = keys(%areas)+1; $area_tag[$id] = $tag; }
    # links data
    for (my $i = 0; $i < $lc; $i++) {
      !$gz ? read F, $_, 32 : $gz->gzread($_, 32);
      push @stat, [$id, unpack('S4 L6', $_)];
      my ($z,$n,$f,$p) = unpack 'S4', $_;
      $links{$p ? "$z:$n/$f.$p" : "$z:$n/$f"} = 1;
      $INB += $stat[-1][9]; $OUTB += $stat[-1][10];
    }
  }
  $gz->gzclose if $gz;
  close F;
};
  if ($@) {
    if ($warn) { print STDERR " * error processing, skipped\n" if $DBG; }
    else { die $@; }
  }
}
# --------------------------------------------------------------------
# parse hpt config
sub parse_config {
  my $in_link;
  local *F;
  my ($name) = @_;
  print STDERR " * processing config file: $name\n" if $DBG;
  open F, $name or die "Can't open husky config file $name\n";
  while (<F>) {
    chomp $_; study $_;
    # strip comments and empty lines
    next if /^#/;
    s/\s+#\s+.*$//;
    next if /^\s*$/;
    # parse stat file
    if (/^\s*advStatisticsFile\s+/i) {
      my @s = /^\s*\S+\s+(?:"(.*?)(?<!\\)"|(\S+))/;
      $stat_file = $s[0].$s[1];
      $stat_file =~ s/\[([^\]]+)\]/$SET{$1} or $ENV{$1}/eg;
      print STDERR " * found advStatisticsFile: $stat_file\n" if $DBG;
    }
    # parse area
    elsif (/^\s*echoarea\s+/i) {
      my @s = /^\s*\S+\s+(?:"(.*?)(?<!\\)"|(\S+))/;
      my $tag = $s[0].$s[1];
      $config_areas{$tag} = {uplink=>undef, links=>[]};
      s/-[Aa]\s+\S+//;
      s/-[Dd]\s+\"[^\"]+\"//;
      my @arr = m!([*\d]+:[*\d]+/[*\d]+(?:\.[*\d]+)?)((?:\s+-\S+)*)!g;
      for (my $i = 0; $i < @arr; $i += 2) {
        $arr[$i] =~ s/\.0+$//;
        if ($arr[$i+1] =~ /-def/i) { $config_areas{$tag}{'uplink'} = $arr[$i]; }
        else { push @{$config_areas{$tag}{'links'}}, $arr[$i]; }
      }
    }
    # parse link
    elsif (/^\s*link\s+/i) { $in_link = 1; }
    elsif ($in_link && /^\s*aka/i) {
      my ($aka) = /^\s*\S+\s+(\S+)/;
      $aka =~ s/\.0+$//;
      push @config_links, $aka;
    }
    # parse set
    elsif (/^\s*set\s+/i) {
      my ($s1, $s2) = /^\s*\S+\s+(\S+)[^=]*=\s*"?(.*?)"?\s*$/o;
      $s2 =~ s/\[([^\]]+)\]/$SET{$1} or $ENV{$1}/eg;
      print STDERR " * found set: $s1=$s2\n" if $DBG;
      $SET{$s1} = $s2;
    }
    # parse include
    elsif (/^\s*include\s+/i) {
      my @s = /^\s*\S+\s+(?:"(.*?)(?<!\\)"|(\S+))/o;
      my $s = $s[0].$s[1];
      $s =~ s/\[([^\]]+)\]/$SET{$1} or $ENV{$1}/eg;
      parse_config($s) if -r $s;
    }
  }
  close F;
}
# --------------------------------------------------------------------
# traffic to string: traf2str($traf); format: ###x or #.#x, x=[kMG]
sub traf2str {
  my $s = ''; my @symb = ('', 'k', 'M', 'G');
  for my $cc (@_) {
    my $x = 0; my $c = $cc;
    if ($c < 0.1) { $s .= ' -- '; next; }
    while ($c >= 1000) { $c /= 1024; $x++; }
    if ($c < 10) { $s .= sprintf "%3.1f%s", $c < 9.95 ? $c : 9.9, $symb[$x]; }
    else { $s .= sprintf "%3d%s", $c, $symb[$x]; }
  }
  return $s;
}
# --------------------------------------------------------------------
# percents to string: perc2str($actual, $base); format: ##.#%
sub perc2str {
  my ($actual, $base) = (@_, 1);
  if ($base == 0) { return ' --  '; }
  elsif ($actual > 0.9995*$base) { return ' 100%'; }
  else { return sprintf "%4.1f%%", 100*$actual/$base; }
}
# --------------------------------------------------------------------
#
sub out_histgr {
# my @symb = (' ', 'ß', 'Ü', 'Û');
  my @symb = ('ú', '±', '²', 'Û');
  my (@sum, @out);
  my $len = 50;

  my ($arr, $type, $max, $maxlen, $totals) = @_;
  for my $v (@$arr) {
    for (my $i = 2; $i < @$v; $i++) { $sum[$i] += $v->[$i]; }
  }
  my $title = @$arr.' '.lc($type).'(s)';
  if ($maxlen < length($title)) { $maxlen = length($title); }
  my $cnt = @{$arr->[0]} - 2;
  my $clen = $maxlen + 3 + $cnt*11;
  $len = 78-$clen if $len > 78-$clen;
  push @out,
       sprintf("%-${maxlen}s  %-${len}s %-10s %-10s\n", $type, '', ' Incoming', ' Outgoing').
       ('Ä'x$maxlen).' Ú'.('Ä'x$len).'¿ '.('Ä'x10).' '.('Ä'x10);
  for my $v (@$arr) {
    my $s = sprintf "%-${maxlen}s ³", $v->[0];
    for (my $l = 0; $l < $len; $l++) {
      my $ch = 0;
      $ch |= 1 if ($len*$v->[2]/$max > $l);
      $ch |= 2 if ($len*$v->[3]/$max > $l);
      $s .= $symb[$ch];
    }
    $s .= "³";
    for (my $i = 2; $i < 2+$cnt; $i++) {
      $s .= sprintf " %4s %s", traf2str($v->[$i]), perc2str($v->[$i], $sum[$i]);
    }
    push @out, $s;
  }
  push @out, ('Ä'x$maxlen).' À'.('Ä'x$len).'Ù '.('Ä'x10).' '.('Ä'x10);
  my ($s2, $s3) = ($totals < 2) ? @sum[2,3] : ($INB, $OUTB);
  push @out, sprintf "%${maxlen}s  %${len}s  %4s %s %4s %s",
         $title, '', traf2str($sum[2]), perc2str($sum[2], $s2),
         traf2str($sum[3]), perc2str($sum[3], $s3) if $totals;
  return @out;
}
# --------------------------------------------------------------------
# make_histgr($type, $sort_field, $tosum, $toout[, $count[, $totals]])
#     type       - Area or Link
#     sort_field - 0 to sort by area/link,
#                  1 to sort by sum of $tosum fields,
#                  2... to sort by corresponding $toout field
#     tosum      - pointer to array of fields to make sum of
#     toout      - pointer to array of fields to include into output
#     count      - make histogram of top $count items
#     totals     - totals line percents mode: 0 - no totals, 1 - 100%,
#                  2 - ratio of listed items/total traffic
sub make_histgr {
  my (@arr, $cur, $prev);
  my ($max, $maxlen) = (0, 0);

  my ($type, $sf, $tosum, $toout, $cnt, $totals) = @_;
  for my $v (@stat) {
    # index by rec
    if ($type eq 'Area') { $cur = $area_tag[$v->[0]]; }
    elsif ($type eq 'Link') {
      $cur = $v->[1].':'.$v->[2].'/'.$v->[3];
      $cur .= '.'.$v->[4] unless $v->[4] == 0;
    }
    # find rec by index
    my $c;
    for ($c = 0; $c <= @arr; $c++) {
      push @arr, [$cur] if $c == @arr;
      last if $arr[$c][0] eq $cur;
    }
    next unless defined $c;
    # update rec
    for my $i (@$tosum) { $arr[$c][1] += $v->[$i]; }
    for (my $i = 0; $i < @$toout; $i++) {
      $arr[$c][$i+2] += $v->[$toout->[$i]];
      $max = $arr[$c][$i+2] if $arr[$c][$i+2] > $max;
    }
    $maxlen = length $arr[$c][0] if $maxlen < length $arr[$c][0];
  }
  # nothing to do
  return () if (@arr <= 0);
  # sort
  if ($sf > 0) { @arr = sort { $b->[$sf] <=> $a->[$sf] } @arr; }
          else { @arr = sort { $a->[$sf] cmp $b->[$sf] } @arr; }
  # make top array
  splice @arr, $cnt, $#arr if $cnt > 0;
  $totals = !($cnt > 0) unless defined $totals;
  return out_histgr(\@arr, $type, $max, $maxlen, $totals);
}
# --------------------------------------------------------------------
#
sub make_summary {
  my (@arr, @tot, @out, $cur, $len);

  my ($type, $sf, $empty) = @_;
  # process stat
  for my $v (@stat) {
    # index by rec
    if ($type eq 'Area') { $cur = $area_tag[$v->[0]]; }
    elsif ($type eq 'Link') {
      $cur = $v->[1].':'.$v->[2].'/'.$v->[3];
      $cur .= '.'.$v->[4] unless $v->[4] == 0;
    }
    # find rec by index
    my $c;
    for ($c = 0; $c <= @arr; $c++) {
      push @arr, [$cur] if $c == @arr;
      last if $arr[$c][0] eq $cur;
    }
    next unless defined $c;
    # update record
    for (my $i = 5; $i <= 11; $i++) {
      $arr[$c][$i-4] += $v->[$i];
      $tot[$i-4] += $v->[$i];
    }
    $maxlen = length $arr[$c][0] if $maxlen < length $arr[$c][0];
  }
  # parse hpt config to find empty areas
  if ($empty) {
    ##parse_config() unless defined %config_areas || defined @config_links;
    if ($type eq 'Area') {
      for my $v (keys %config_areas) { push @arr, [$v] if !$areas{$v}; }
    } elsif ($type eq 'Link') {
      for my $v (@config_links) { push @arr, [$v] if !$links{$v}; }
    }
  }
  # sort
  if ($sf > 0) { @arr = sort { $b->[$sf] <=> $a->[$sf] } @arr; }
          else { @arr = sort { $a->[$sf] cmp $b->[$sf] } @arr; }
  # make out
  $len = 78 - (1+11+1+11+1+4+1+4+1+10+1+10);
  push @out, sprintf("%-${len}s", $type).'   In msgs     Out msgs   Bad Dupe  In bytes   Out bytes';
  push @out, ('Ä'x$len).' '.('Ä'x11).' '.('Ä'x11).' '.('Ä'x4).' '.('Ä'x4).' '.('Ä'x10).' '.('Ä'x10);
  for my $v (@arr) {
    my $s = $v->[0];
    if (length $s > $len) { substr $s, $len-3, length($s)-$len+3, '...'; }
    push @out, sprintf("%-${len}s %5s %s %5s %s %4s %4s %4s %s %4s %s",
               $s,
               ($v->[1] || '-'), perc2str($v->[1], $tot[1]),
               ($v->[2] || '-'), perc2str($v->[2], $tot[2]),
               ($v->[4] || '-'), ($v->[3] || '-'),
               traf2str($v->[5]), perc2str($v->[5], $tot[5]),
               traf2str($v->[6]), perc2str($v->[6], $tot[6]));
  }
  push @out, sprintf "%${len}s", "No data available" unless @arr > 0; # nothing to out
  push @out, ('Ä'x$len).' '.('Ä'x11).' '.('Ä'x11).' '.('Ä'x4).' '.('Ä'x4).' '.('Ä'x10).' '.('Ä'x10);
  push @out, sprintf("%${len}s %5s %s %5s %s %4s %4s %4s %s %4s %s",
             "Total ".@arr." ".lc($type)."(s)",
             ($tot[1] || '-'), perc2str($tot[1], $tot[1]),
             ($tot[2] || '-'), perc2str($tot[2], $tot[2]),
             ($tot[4] || '-'), ($tot[3] || '-'),
             traf2str($tot[5]), perc2str($tot[5], $tot[5]),
             traf2str($tot[6]), perc2str($tot[6], $tot[6])) if @arr > 0;
  return @out;
}
# --------------------------------------------------------------------
# areas with no traffic
sub make_notraf {
  my ($maxlen, @out, $len) = (16);
  ##parse_config() unless defined %config_areas;
  for my $tag (keys %config_areas) {
    next if $areas{$tag};
    if (length $tag > $maxlen) { $maxlen = length $tag; }
  }
  $len = 78 - 18 - $maxlen;
  push @out, sprintf("%-${maxlen}s", 'Area').'      Uplink      Links';
  push @out, ('Ä'x$maxlen).' '.('Ä'x16).' '.('Ä'x$len);
  for my $tag (sort keys %config_areas) {
    next if $areas{$tag};
    my $s = join(' ', @{$config_areas{$tag}{'links'}});
    if (length $s > $len) { substr $s, $len-3, length($s)-$len+3, '...'; }
    push @out, sprintf "%-${maxlen}s %16s %s", $tag,
               $config_areas{$tag}{'uplink'} || 'n/a', $s;
  }
  push @out, "        No areas" unless @out > 2;
  push @out, ('Ä'x$maxlen).' '.('Ä'x16).' '.('Ä'x$len);
  return @out;
}
# --------------------------------------------------------------------
# links and areas with bad or dupe messages
sub make_baddupe {
  my (@out, @arr, @tot, $len, $s, $i);
  my (%was_area, %was_link);
  my ($titles, $sf, $tosum, $toout) = @_;
  for my $v (@stat) {
    for ($i = 0; $i <= @$toout; $i++) { last if $v->[$toout->[$i]] > 0; }
    next if ($i == @$toout);
    my $tag = $area_tag[$v->[0]];
    # sum - sort field
    my $sum = 0;
    for my $i (@$tosum) { $sum += $v->[$i]; }
    # out rec
    $link = $v->[1].':'.$v->[2].'/'.$v->[3].($v->[4] ? '.'.$v->[4] : '');
    my @rec = ($tag, $link, $sum);
    for my $i (@$toout) { push @rec, $v->[$i]; $tot[$i] += $v->[$i]; }
    push @arr, \@rec;
    # calc totals
    $was_area{ $v->[0] } = 1;
    $was_link{ $link } = 1;
  }
  # sort
  if ($sf > 2) { @arr = sort { $b->[$sf] <=> $a->[$sf] } @arr; }
          else { @arr = sort { $a->[$sf] cmp $b->[$sf] } @arr; }
  # make out
  $len = 78 - 17 - 5*@$toout;
  $s = sprintf("%-${len}s", 'Area').'       Link      ';
  for (my $i = 0; $i < @$toout; $i++) { $s .= ' '.$titles->[$i]; }
  push @out, $s;
  $s = ('Ä'x$len).' '.('Ä'x16);
  for (my $i = 0; $i < @$toout; $i++) { $s .= ' '.('Ä'x4); }
  push @out, $s;
  for my $rec (@arr) {
    my $ss = $rec->[0];
    if (length $ss > $len) { substr $ss, $len-3, length($ss)-$len+3, '...'; }
    $s = sprintf "%-${len}s %16s", $ss, $rec->[1];
    for ($i = 0; $i < @$toout; $i++) { $s .= ' '.sprintf "%4s", $rec->[$i+3] || '-'; }
    push @out, $s;
  }
  push @out, "      No records" unless @arr > 0;
  $s = ('Ä'x$len).' '.('Ä'x16);
  for (my $i = 0; $i < @$toout; $i++) { $s .= ' '.('Ä'x4); }
  push @out, $s;
  if (@arr > 0) {
    $s = sprintf "%${len}s %16s", 'Total '.keys(%was_area).' area(s)', keys(%was_link).' link(s)';
    for my $i (@$toout) { $s .= ' '.sprintf "%4s", $tot[$i] || '-'; }
    push @out, $s;
  }
  return @out;
}
# --------------------------------------------------------------------
# debug output of @stat array; optionally sort by specified column
sub debug_stat {
  my @sorted;
  my ($sort) = @_;
  if ($sort) { @sorted = sort { $b->[$sort] <=> $a->[$sort] } @stat; }
  printf "%-30s %-16s\t In Out Dup Bad   In b Out b\n", "Tag", "Address";
  printf "%s %s\t--- --- --- ---  ----- -----\n", '-'x30, '-'x16;
  for my $arr ($sort ? @sorted : @stat) {
    printf "%-30s %d:%d/%d.%d\t%3d %3d %3d %3d  %5d %5d\n", $area_tag[$arr->[0]], @$arr[1..$#$arr];
  }
}
# --------------------------------------------------------------------
# convert string to datetime: str2time($s[, $base])
sub str2time {
  die "POSIX perl module is required for archive processing\n" unless eval { require POSIX; 1; };
  my ($s, $base) = @_;
  $base = time if !defined $base;
  my ($h, $d, $m, $y, $w) = (localtime $base)[2..6];
  $w = 7 if $w == 0;
  $h = 0 unless $s =~ /[Hh]/o;
  while (length $s > 0) {
    my @a = $s =~ /^([+-]?)(\d+)([hHdDwWmMyY])?/o or return undef;
    substr $s, 0, length(join '', @a), '';
    $a[2] = 'd' if !defined $a[2];
    if (lc $a[2] eq 'y') {
      if ($a[0] eq '-') { $y -= $a[1]; }
      elsif ($a[0] eq '+') { $y += $a[1]; }
      elsif ($a[1] < 1900) { $y = $a[1]+100; }
      else { $y = $a[1]-1900; }
    }
    elsif (lc $a[2] eq 'm') { $m = $a[0] eq '-' ? $m-$a[1] : $a[1]-1;
      if ($a[0] eq '-') { $m -= $a[1]; }
      elsif ($a[0] eq '+') { $m += $a[1]; }
      else { $m = $a[1] - 1; }
    }
    elsif (lc $a[2] eq 'w') {
      if ($a[0] eq '-') { $d -= $w+7*$a[1]-1; $w = 1; }
      elsif ($a[0] eq '+') { $d += 7*$a[1]-$w+1; $w = 1; }
      else { return undef; }
    }
    elsif (lc $a[2] eq 'd') {
      if ($a[0] eq '-') { $d -= $a[1]; }
      elsif ($a[0] eq '+') { $d += $a[1]; }
      else { $d = $a[1]; }
    }
    elsif (lc $a[2] eq 'h') {
      if ($a[0] eq '-') { $h -= $a[1]; }
      elsif ($a[0] eq '+') { $h += $a[1]; }
      else { $h = $a[1]; }
    }
  }
  return POSIX::mktime(0, 0, $h, $d, $m, $y, $w);
}
# --------------------------------------------------------------------
# command line parser
sub parse_cmdline {
  my $i;
  for ($i = 0; $i < @ARGV; $i++) {
    if ($ARGV[$i] eq '-c') {
      die "Use: -c <config file>\n" if $i+1 >= @ARGV;
      $conf_file = $ARGV[$i+1]; $i++;
    }
    elsif ($ARGV[$i] =~ /^--conf/io) {
      ($conf_file) = $ARGV[$i] =~ /^--conf=(.+)$/io or die "Use: --conf=<conf-file>\n";
    }
    elsif ($ARGV[$i] =~ /^(?:-z|--[Gg][Zz])$/) { $GZ = 1; }
    elsif (lc $ARGV[$i] eq '-a') {
      die "Use: -a <archive layout> <start date> <period>\n" if $i+3 >= @ARGV;
      $archive = $ARGV[$i+1];
      $dt1 = str2time($ARGV[$i+2]) or die "Bad date format: ".$ARGV[$i+2]."\n";
      $dt2 = str2time($ARGV[$i+3], $dt1) or die "Bad date format: ".$ARGV[$i+3]."\n";
      $i += 3;
    }
    elsif ($ARGV[$i] =~ /^--arch/io) {
      my ($s1, $s2);
      ($archive, $s1, $s2) = $ARGV[$i] =~ /^--arch=([^,]+),([^,]+),([^,]+)$/io or die "use: --arch=<archive-layout>,<start-date>,<period>\n";
      $dt1 = str2time($s1) or die "Bad date format: $s1\n";
      $dt2 = str2time($s2, $dt1) or die "Bad date format: $s2\n";
    }
    elsif ($ARGV[$i] =~ /^(?:-h|-\?|--[Hh][Ee][Ll][Pp])$/o) { print USAGE(); exit; }
    elsif ($ARGV[$i] =~ /^(?:-D|--[Dd][Ee][Bb][Uu][Gg])$/o) { $DBG = 1; }
    elsif (-f $ARGV[$i]) { push @stat_file, $ARGV[$i]; last; }
    else { die "Unknown parameter or missing stat file: $ARGV[$i]\n"; }
  }
  for (; $i < @ARGV; $i++) {
    if (-f $ARGV[$i]) { push @stat_file, $ARGV[$i]; last; }
    else { die "Missing stat file: $ARGV[$i]\n"; }
  }
}
# --------------------------------------------------------------------
# init
sub init {
  $GZ = 0;
  parse_cmdline;
  # parse config _only_ if we know its name
  $conf_file = $ENV{FIDOCONFIG} || $_[1] unless defined $conf_file;
  parse_config($conf_file) if defined $conf_file;
  # parse stat archive
  if (defined $archive) {
    print STDERR " * period: ".localtime($dt1)."-".localtime($dt2)."\n * archive layout: $archive\n" if $DBG;
    for (my $i = $dt1; $i < $dt2; $i += 3600*24) {
      #print STDERR " * strftime=".POSIX::strftime($archive, (localtime($i))[0..5])." for date ".localtime($i)."\n" if $DBG;
      parse_stat( POSIX::strftime($archive, (localtime($i))[0..5]), 1 );
    }
  }
  # parse several stat files
  elsif (@stat_file > 0) {
    for $stat_file (@stat_file) { parse_stat($stat_file); }
  }
  # parse one stat file only
  else {
    $stat_file = $_[0] unless defined $stat_file;
    die "Please specify statfile in cmdline, parse_stat() or advStatisticsFile keyword\n" unless defined $stat_file;
    parse_stat($stat_file);
  }
}

sub USAGE () { return <<EOF
advhptstat ver.$ver, (c)opyright 2002-03, by val khokhlov

  Usage: advhptstat [options] [stat file...]
  Options are:
    -c <config>, --conf=<config>           specifies config file name
    -z, --gz                               force use gzip'ed binary stat logs
  Instead of one or more stat files you can use archive for a period:
    -a <layout> <start> <end>, --arch=<layout>,<start>,<end>
       <layout> - full filename of a stat log for a day if strftime() format
       <start>  - start date of period (see below for format)
       <end>    - end date of period (actually, *not* inclusive)

  date <start>, <end> consists of token(s): [+-]<NN>[hdwmy]
       use 15x to set value to 15 (h - hour, d - day, m - month, y - year)
       use +2d to advance day forward by 2, -6d to advance day backward by 6
       use -1w to set date to Monday of previous week, +1w - next week
       (if letter [hdwmy] is omitted 'd' is assumed)

  Examples (assume now is 17 Jan 2003):
     advhptstat hpt.stat.bin               -- simply use hpt.stat.bin
     advhptstat -a "/home/fido/log/%Y/%m/%d/hpt.sta.gz" -7 +7
       -- will use files: /home/fido/log/2003/01/##/hpt.sta.gz, ##=10..16
EOF
}
