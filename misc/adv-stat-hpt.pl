#!/usr/bin/perl
# hptstat ver.0.4, (c)opyright 2002-03, by val khokhlov
$areas = 0;                   # areas count
@area_tag;                    # array of area tags ($tag -> $name)
%links;                       # links found in stat
@stat;                        # array ($tag, @addr, @msgs, @bytes)
                              # idx: 0  1 2 3 4 5  6   7    8   9   10
                              # val: id z:n/f.p in out dupe bad inb outb
$INB = $OUTB = 0;             # total input and output bytes
%config_areas, @config_links; # parsed hpt config

parse_config($ENV{FIDOCONFIG} or "/home/val/fido/hpt/hpt.conf");
parse_stat($stat_file or "d:/fido/log/hpt.stat.bin");
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

# --------------------------------------------------------------------
# center a line
sub center { return sprintf '%'.(39-length($_[0])/2)."s%s\n", ' ', $_[0]; }
# --------------------------------------------------------------------
# find area number by tag
sub find_area {
  my ($tag, $add) = @_;
  for (my $i = 0; $i < $areas; $i++) {
    return $i if ($tag eq $area_tag[$i]);
  }
  if ($add) { push @area_tag, $tag; return $areas++; } else { return undef; }
}
# --------------------------------------------------------------------
# parse stat file into $areas
sub parse_stat {
  my ($name) = @_;
  die "Please specify statfile in parse_stat() or advStatisticsFile config keyword\n" unless defined $name;
  open F, $name or die "Can't open stat file $name\n"; binmode F;
  read F, $_, 16;
  my ($rev, $t0) = unpack 'x2 S1 L1', $_;
  # check revision
  if ($rev != 1) { close F; die "Stat file $name revision $rev, expected 1\n"; }
  # set times
  $stat1 = $t0; $stat2 = (stat F)[9];
  # read file
  while (!eof F) {
    read F, $_, 4;
    my ($lc, $tl, $tag) = unpack 'S2', $_;
    # area tag
    read F, $tag, $tl;
    my $id = find_area($tag, 1);
    # links data
    for (my $i = 0; $i < $lc; $i++) {
      read F, $_, 32;
      push @stat, [$id, unpack('S4 L6', $_)];
      my ($z,$n,$f,$p) = unpack 'S4', $_;
      $links{$p ? "$z:$n/$f.$p" : "$z:$n/$f"} = 1;
      $INB += $stat[-1][9]; $OUTB += $stat[-1][10];
    }
  }
  close F;
}
# --------------------------------------------------------------------
# parse hpt config
sub parse_config {
  my $in_link;
  my ($name) = @_;
  die "Please define FIDOCONFIG variable or specify husky config name\n" unless length $name > 0;
  open F, $name or die "Can't open husky config file $name\n";
  while (<F>) {
    chomp $_; study $_;
    # strip comments and empty lines
    next if /^#/;
    s/\s+#\s+.*$//;
    next if /^\s*$/;
    # parse stat file
    if (/^\s*advStatisticsFile\s+/i) {
      ($stat_file) = /^\s*\S+\s+(\S+)/;
    }
    # parse area
    elsif (/^\s*echoarea\s+/i) {
      my ($tag) = /^\s*\S+\s+(\S+)/;
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
      for my $v (keys %config_areas) { push @arr, [$v] if !defined find_area($v); }
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
               ($v->[3] || '-'), ($v->[4] || '-'),
               traf2str($v->[5]), perc2str($v->[5], $tot[5]), 
               traf2str($v->[6]), perc2str($v->[6], $tot[6]));
  }
  push @out, sprintf "%${len}s", "No data available" unless @arr > 0; # nothing to out
  push @out, ('Ä'x$len).' '.('Ä'x11).' '.('Ä'x11).' '.('Ä'x4).' '.('Ä'x4).' '.('Ä'x10).' '.('Ä'x10);
  push @out, sprintf("%${len}s %5s %s %5s %s %4s %4s %4s %s %4s %s",
             "Total ".@arr." ".lc($type)."(s)", 
             ($tot[1] || '-'), perc2str($tot[1], $tot[1]), 
             ($tot[2] || '-'), perc2str($tot[2], $tot[2]), 
             ($tot[3] || '-'), ($tot[4] || '-'),
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
    next if find_area($tag);
    if (length $tag > $maxlen) { $maxlen = length $tag; }
  }
  $len = 78 - 18 - $maxlen;
  push @out, sprintf("%-${maxlen}s", 'Area').'      Uplink      Links';
  push @out, ('Ä'x$maxlen).' '.('Ä'x16).' '.('Ä'x$len);
  for my $tag (sort keys %config_areas) {
    next if find_area($tag);
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
  my (@out, @arr, @tot, $len, $s);
  my ($titles, $sf, $tosum, $toout) = @_;
  for my $v (@stat) {
    for (my $i = 0; $i <= @$toout; $i++) { last if $v->[$i] > 0; }
    next if ($i == @toout);
    my $tag = $area_tag[$v->[0]];
    # sum - sort field
    my $sum = 0;
    for my $i (@$tosum) { $sum += $v->[$i]; }
    # out rec
    $link = $v->[1].':'.$v->[2].'/'.$v->[3].($v->[4] ? '.'.$v->[4] : '');
    my @rec = ($tag, $link, $sum);
    for my $i (@$toout) { push @rec, $v->[$i]; $tot[$i] += $v->[$i]; }
    push @arr, \@rec;
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
    for ($i = 0; $i < @$toout; $i++) { $s .= sprintf "%-4s", $rec->[$i+3] || '-'; }
    push @out, $s;
  }
  push @out, "      No records" unless @arr > 0;
  $s = ('Ä'x$len).' '.('Ä'x16);
  for (my $i = 0; $i < @$toout; $i++) { $s .= ' '.('Ä'x4); }
  push @out, $s;
  if (@arr > 0) {
    $s = sprintf "%${len}s %16s", 'Total '.$areas.' area(s)', $links.' link(s)';
    for my $i (@$toout) { $s .= sprintf "%-4s", $tot->[$i] || '-'; }
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
