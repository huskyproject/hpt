#!/usr/bin/perl
# ====================================================================
#             Bink-style Outbound Unpacker      
# version 1.0                              (C)opyright by val khokhlov
# ====================================================================
# default outbound zone
$DEF_ZONE  = 2;
# outbound dirs - first one should be main outbound and unpack will
# look other outbounds for this domain; other domains' outbounds
# should be explicitly specified here
@OUTBOUND  = ('/home/val/fido/outbound');
# netmail (.msg) directory to unpack into
$MSG_DIR   = '/home/val/fido/mail/in';
# if set, last via line will be stripped
$STRIP_VIA = 0;
# max number of tries for .bsy to disappear
$MAX_TRY   = 3;
# initial delay in seconds between tries, will be doubled each try
$TRY_DELAY = 10;
# log file, if unset log to stdout
$LOG       = '/home/val/fido/log/unpack.log';
# log a string
sub say {
  my @mon = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
  printf LOG "%s %2d %02d:%02d:%02d ", $mon[(localtime)[4]], (localtime)[3,2,1,0] if defined $LOG;
  print LOG "  " x $cur_lvl;
  print LOG $_[1]."\n";
}
# my basename function (works for dos and unix)
sub basename { return ($_[0] =~ /[^\\\/]+$/o) ? $& : undef; }
# get_msgno($msgdir)
sub get_msgno {
  my ($dir) = @_;
  return undef unless (-d $dir);
  my $max = 0;
  opendir DIR, $dir;
  while ($_ = readdir DIR) { if (/^(\d+)\.[mM][sS][gG]$/o) { $max = $1 if ($1 > $max); } }
  closedir DIR;
  return $max;
}
# convert bso name to net/node
sub bso2node {
  return hex(substr $_[0], 0, 4).'/'.hex(substr $_[0], 4, 4);
}
# unpack_bso($dir, $base_node=undef)
sub unpack_bso {
#  local ($_, $nname, $ext);
  my $ok = 1;
  my ($dir, $base) = @_;
  return $ok unless (-d $dir);
  # get zone number
  if ($dir =~ /\.(\d{3})$/) { $zone = hex $1; }
  elsif (!defined $base) { $zone = $DEF_ZONE; }
  say 5, "Processing directory $dir".(defined $base ? " (node $zone:".bso2node($base).")" : " (zone $zone)");
  $cur_lvl++;
  # read directory
  opendir DIR, $dir;
  my @files = readdir DIR;
  closedir DIR;
  # process files
  my $i = 0; my ($name, $ext, $nname); my @todo = ();
  my (@uts, @los, $pnt);
  @files = sort { lc $a <=> lc $b } @files;
  for (@files) {
    next if (/^\.\.?$/);
    if (!/^([0-9A-Fa-f]{8})\.([ochdi]ut|[fchdi]lo|pnt)$/io) {
      say 8, "File $_: not BSO-compliant name, skipped";
      next;
    }
    $ext = $2; $nname = $1;
    if (lc $nname ne lc $name) {
      if (defined $name) {
        say 5, "Processing ".(defined $base ? "point $zone:".bso2node($base).".".hex($name) : "node $zone:".bso2node($name))." ($name.*)" if @uts > 0;
        $ok &= process_node($dir, $name, \@uts, \@los, $pnt); 
      }
      $name = $nname;
      @uts = (); @los = (); $pnt = undef;
    }
    if (lc $ext eq 'pnt') { 
      if (defined $base) { say 8, "Directory $_: should not be here, skipped"; }
      else { $pnt = $_; }
    }
    elsif ($ext =~ /^.[uU][tT]$/o) { push @uts, $_; }
    elsif ($ext =~ /^.[lL][oO]$/o) { push @los, $_; }
  }
  if (defined $name) {
    say 5, "Processing ".(defined $base ? "point $zone:".bso2node($base).".".hex($name) : "node $zone:".bso2node($name))." ($name.*)" if @uts > 0;
    $ok &= process_node($dir, $name, \@uts, \@los, $pnt); 
  }
  $cur_lvl--;
  if ($dir eq $OUTBOUND[0]) { say 8, "Finished $dir"; }
  else { say 8, "Finished, remove $dir status=".rmdir($dir); }
  return $ok;
}
# process_node($dir, $name, \@uts, \@los, $pnt)
sub process_node {
  my ($dir, $name, $uts, $los, $pnt) = @_;
  my %attaches = ();
  # check busy
  if (-e $dir.'/'.$name.'.'.'bsy') {
    say 5, "> note: there's busy flag $name.bsy, skipping node";
    return 0;
  }
  # create our own busy
  if (!open BSY, ">$dir/$name.bsy") { 
    say 5, "> error: unable to create busy flag $name.bsy, skipping node"; 
    return 0; 
  }
  close BSY;
  # process all .ut's
  for my $pkt (@$uts) { 
    unlink "$dir/$pkt" if process_pkt("$dir/$pkt", \%attaches);
  }
  # delete all attaches that are in unpacked messages
  if (@$uts > 0) {
    for my $lo (@$los) {
      my $old = $lo;
      my $new = $old; $new =~ s/\.(.)../\.$1\$\$/;
      if (!open F, $dir.'/'.$old) {
        say 5, "> error: unable to open file $dir/$old"; next;
      }
      if (!open G, '>'.$dir.'/'.$new) {
        say 5, "> error: unable to create file $dir/$new"; close F; next;
      }
      my $cnt = 0; my $s = undef;
      while ($s = <F>) {
        if ($s =~ /[#^]?(.*?)\r?\n/) {
          if (defined $attaches{basename $1}) { $attaches{basename $1}++; }
          else { print G $s; $cnt++; }
        }
        else { print G $s; $cnt++; }
      }
      close F; close G;
      unlink $dir.'/'.$old; 
      if ($cnt > 0) { rename $dir.'/'.$new, $dir.'/'.$old; }
      else { unlink $dir.'/'.$new; }
    }
  }
  # warn about attaches
  for my $s (keys %attaches) { 
    say 8, "> warn: attached file $s not found in .lo's" unless $attaches{$s}; 
  }
  # delete busy
  unlink "$dir/$name.bsy";
  # process point dir
  my $ok = 1;
  $ok = unpack_bso($dir.'/'.$pnt, $name) if (defined $pnt);
  return $ok;
}
# process_pkt($name, \%attaches)
sub process_pkt {
  my ($name, $attaches) = @_;
  # try to read packet
  if (!open PKT, $name) {
    say 5, "> error: unable to open packet $name"; return 0;
  }
  binmode PKT; my $buf;
  if (!defined read PKT, $buf, -s PKT) {
    say 5, "> error: unable to read packet $name"; return 0;
  }
  close PKT;
  say 8, "> processing packet $name";
  my $msgn0 = $msgno; my @msgs; my $ok = 1;
  # check pkt header
  my $pos, $len = 58;
  my $hdr = substr $buf, 0, $len, ''; $pos += $len;
  # read messages one by one
  while (unpack('S', $buf) != 0) {
    my ($ver, $of, $df, $on, $dn, $attr, $cost, $dt) = unpack 'S7 Z20', $buf;
    substr $buf, 0, 34, '';
    if ($ver != 2) {
      say 5, "> error: bad msg version (2 expected) at pos ".sprintf("%08x", $pos);
      $ok = 0; last;
    }
    if ($buf !~ /^([^\0]{0,36}\0)([^\0]{0,36}\0)([^\0]{0,72}\0)([^\0]*\0)/o) {
      say 5, "> error: bad pkt format at pos ".sprintf("%08x", $pos+34);
      $ok = 0; last;
    }
    my($to, $from, $subj, $text) = ($1, $2, $3, $4);
    $len = length($to)+length($from)+length($subj)+length($text);
    substr $buf, 0, $len, ''; $pos += $len+34;
    # try to get point and zone from message
    if ($text =~ /(?:^|\r)\x01FMPT (\d+)(?:$|\r)/) { $op = $1; }
    if ($text =~ /(?:^|\r)\x01TOPT (\d+)(?:$|\r)/) { $dp = $1; }
    if ($text =~ /(?:^|\r)\x01INTL (\d+):(\d+)\/(\d+) (\d+):(\d+)\/(\d+)(?:$|\r)/) { 
      $oz = $4; $dz = $1;
    } else { $oz = $dz = $zone; }
    # if this message is file-attach, store file names from subj
    if ($attr & 0x10) {
      my @files = $subj =~ /([^ ,\0]+)/go;
      for my $f (@files) { $attaches->{basename $f} = 0; }
    }
    # strip last via
    if ($STRIP_VIA) {
      pos($text) = rindex($text, "\r\x01Via ") + 1;
      $text =~ s/\G\x01Via [^\r]+\r//;
    }
    # make message
    my $msg = pack 'Z36 Z36 Z72 Z20 s11 S1 s1', $from, $to, $subj, $dt, 0, 
              $df, $of, $cost, $on, $dn, $dz, $oz, $dp, $op, 0, $attr, 0;
    $msg .= $text;
    # write message
    $msgno++;
    if (!open MSG, ">$msgdir/$msgno.msg") { 
       say 5, "> error: can't create message $msgdir/$msgno.msg; skipping packet";
       $ok = 0; last;
    }
    push @msgs, "$msgdir/$msgno.msg"; binmode MSG;
    if (!print MSG $msg) {
       say 5, "> error: can't write message $msgdir/$msgno.msg; skipping packet";
       $ok = 0; last;
    } 
    close MSG;
  }
  if (!$ok) { unlink @msgs; $msgno = $msgn0; return 0; }
  else { return 1; }
}

sub populate_outbounds {
  my ($base, $name) = $OUTBOUND[0] =~ /^(.*?)([^\/\\]+)[\/\\]?$/;
  opendir D, $base;
  while (my $s = readdir D) {
    next unless ($s =~ /^$name\.[0-9A-Fa-f]+$/);
    my $i;
    for ($i = 0; $i < @OUTBOUND; $i++) { last if ($OUTBOUND[i] eq $s); }
    push @OUTBOUND, $base.$s if ($i == @OUTBOUND);
  }
  closedir D;
}

if (defined $LOG) { 
  open LOG, ">>$LOG" || die "Can't open log $LOG\n"; say 2, "."x63;
} else { open LOG, ">&STDOUT"; }
$msgdir = $MSG_DIR;
$msgno = get_msgno($msgdir);
if (!defined $msgno) { say 2, "Fatal: Can't find directory $msgdir"; exit 1; }
populate_outbounds();
$try = 0; $delay = $TRY_DELAY;
while ($try++ < $MAX_TRY) {
  my $ok = 1;
  foreach my $s (@OUTBOUND) { $ok &= unpack_bso $s; }
  last if ($ok);
  last if ($try >= $MAX_TRY);
  say 5, "Waiting for the busy files to free ($delay sec), try #$try";
  sleep $delay; $delay += $TRY_DELAY;
}
close LOG;
