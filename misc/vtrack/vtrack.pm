{
use strict;
no strict "subs";

our $VERSION = "0.06";

# declare subs
sub PVT(); sub CRA(); sub RCV(); sub SNT(); sub ATT(); sub TRS(); sub ORP(); sub K_S();
sub LOC(); sub HLD(); sub RSV(); sub FRQ(); sub RRQ(); sub RRC(); sub ARQ(); sub URQ();
sub A_S(); sub DIR(); sub ZON(); sub HUB(); sub IMM(); sub XMA(); sub KFS(); sub TFS();
sub LOK(); sub CFM(); sub HIR(); sub COV(); sub SIG(); sub LET();

# do some aliasing
*post  = \&putMsgInArea;
*from  = \$::fromaddr;
*to    = \$::toaddr;
*addr  = \$::toaddr;
*sfrom = \$::fromname;
*sto   = \$::toname;
*subj  = \$::subject;

# figure out basename function
*basename = \&my_basename;
#eval { require File::Basename; *basename = \&File::Basename::basename; };

# return 1 if it's my aka
sub me {
  my $s = $_[0]; $s =~ s/\.0$//;
  for my $aka (@{$::config{addr}}) { return 1 if $aka eq $s; }
  return 0;
}
# addvia($link=undef, $utc=undef)
#     $link - substitute aka for link to via
#     $utc  - set to 1 to use GMT
# add via to the $text; set $change=1, $addvia=0; 
sub addvia {
  my $a = defined $::links{$_[0]}{aka} ? $::links{$_[0]}{aka} : $::config{addr}[0];
  my $offs = '';
  if (!$_[1]) { 
    $offs = gmtoff(); $offs = sprintf("%+g", $offs) unless $offs == 0; 
  }
  $::text .= "\x01Via $a \@".strftime("%Y%m%d.%H%M%S", $_[1] ? gmtime : localtime).
             ".UTC$offs $::hpt_ver+vtrack $VERSION\r";
  $::addvia = 0; $::change = 1;
}
# return age of message in days
sub age () {
  return (time-$::date)/(60*60*24);
}
# return loop count (^via of all our aka's)
sub loop_cnt () {
  my $addrs = '('.join('|', @{$::config{addr}}).')';
  my @vias = $::text =~ /(?:^|\r)\x01Via $addrs /g;
  return scalar @vias;
}
# loop_age([$cnt])
#     $cnt - loop number; return list if $cnt=undef
# return loop age (days ago message passed through our system)
sub loop_age {
  my $addrs = '(?:'.join('|', @{$::config{addr}}).')';
  my @vias = $::text =~ /(?:^|\r)(\x01Via $addrs [^\r]*)/g;
  my @ages;
  for (my $i = 0; $i < @vias; $i++) {
    if (defined $_[0] && ($i != $_[0])) { next; }
    #                                    $1     $2     $3       $4     $5     $6          $7
    my $k = $vias[$i] =~ /^\x01Via\s+\S+\s+\@(\d{4})(\d{2})(\d{2})\.(\d{2})(\d{2})(\d{2})\.UTC([+-]\d+)?/o;
    return undef unless defined $6;
    my $t = mktime($6, $5, $4, $3, ($2)-1, ($1)-1900);
    if (defined $7) { $t += (gmtoff() - $7)*3600; } else { $t += gmtoff()*3600; }
    if (defined $_[0]) { return (time-$t)/(60*60*24); }
    else { push @ages, (time-$t)/(60*60*24); }
  }
  return (@ages) ? @ages : undef;
}
# pack_age()
# return hours since message was packed at my system,
# undef if the last Via isn't my
sub pack_age () {
  my $addrs = '(?:'.join('|', @{$::config{addr}}).')';
  my @a = $::text =~ /(?:^|\r)\x01Via\s+$addrs\s+\@(\d{4})(\d{2})(\d{2})\.(\d{2})(\d{2})(\d{2})\.UTC([+-]\d+)?[^\r]*[\r\s]*$/o;
  return undef unless defined @a;
  my $t = mktime($a[5], $a[4], $a[3], $a[2], $a[1]-1, $a[0]-1900);
  $t += (gmtoff() - $a[6])*3600;
  return (time-$t)/3600;
}
# att_check($flags = 3)
#     $flags - where to find attaches; bit mask:
#              bit 0 (1): secure inbound
#              bit 1 (2): unsecure inbound
#              bit 2 (4): local inbound
# return 1 if all attaches are present or it's non-ATT message
sub att_check {
  return 1 if !($::attr & (ATT | FRQ | URQ));
  my @files = $::subj =~ /([^ ,]+)/go;
  my $where = defined $_[0] ? $_[0] : 3;
  for my $s (@files) {
    $s = basename($s); my $found = 0;
    next unless defined $s;
    if ($where & 1) { $found |= -e $::config{protInbound}.'/'.$s; }
    if ($where & 2) { $found |= -e $::config{inbound}.'/'.$s; }
    if ($where & 4) { $found |= -e $::config{localInbound}.'/'.$s; }
    return 0 unless $found;
  }
  return 1;
}
# return number of attached files, 0 if none but ATT, undef if non-ATT message
sub att_cnt () {
  return undef unless $::attr & (ATT | FRQ | URQ);
  my @files = $::subj =~ /([^ ,]+)/go;
  return scalar @files;
}                                    
# att_size($cnt, $flags = 3)
#     $cnt   - number of attach; return list if $cnt=undef
#     $flags - see att_check()
# return size of given attach, undef if it's not found
sub att_size {
  return undef if !($::attr & (ATT | FRQ | URQ));
  my @files = $::subj =~ /([^ ,]+)/go;
  my $where = defined $_[1] ? $_[1] : 3;
  my @sizes;
  for (my $i = 0; $i < @files; $i++) {
    if (defined $_[0] && $i != $_[0]) { next; }
    my $s = basename($files[$i]); my $size;
    if (defined $s) {
      my $n = 0;
      for my $dir (($::config{protInbound},$::config{inbound},$::config{localInbound})) {
        next unless $where & (1<<$n++);
        if (-e "$dir/$s") { $size = -s "$dir/$s"; last; }
      }
    }
    if (defined $_[0]) { return $size; } else { push @sizes, $size; }
  }
  return (@sizes) ? @sizes : undef;
}
# att_kill($cnt, $flags = 3)
#     $cnt   - number of attach; unlink all if undef
#     $flags - see att_check()
# unlinks attaches of the current message
sub att_kill {
  return unless ($::attr & (ATT | FRQ | URQ));
  my @files = $::subj =~ /([^ ,]+)/go;
  my $where = defined $_[1] ? $_[1] : 3;
  for (my $i = 0; $i < @files; $i++) {
    if (defined $_[0] && $i != $_[0]) { next; }
    my $s = basename($files[$i]);
    if (defined $s) {
      my $n = 0;
      for my $dir (($::config{protInbound},$::config{inbound},$::config{localInbound})) {
        next unless $where & (1<<$n++);
        if (-e "$dir/$s") { unlink "$dir/$s"; last; }
      }
    }
  }
}
# att_conv($cnt)
#     $cnt   - number of attach; all if undef
# strip directory from attach file name
sub att_conv {
  return unless ($::attr & (ATT | FRQ | URQ));
  my @files = $::subj =~ /([^ ,]+)/go;
  my $same = 1;
  for (my $i = 0; $i < @files; $i++) {
    next if (defined $_[0] && $i != $_[0]);
    my $s = basename($files[$i]);
    if ($s ne $files[$i]) { $files[$i] = $s; $same = 0; }
  }
  if (!$same) { $::subj = join ' ', @files; $::change = 1; }
  return $same;
}
# msg_dekludge([$delim]) - remove kludges from the message
sub msg_dekludge {
  my @res = $::text =~ /(?:^|\r)([^\x01][^\r]*)/go;
  return join $_[0]||"\r", @res;
}
# msg_kludges([@list]) - return kludges from the message
sub msg_kludges {
  my @klgs = @_ ? @_ : qw(INTL TOPT FMPT MSGID REPLY FLAGS);
  my $klgs = '(?:'.join('|', @klgs).')';
  my @res = $::text =~ /(?:^|\r)(\x01$klgs[^\r]*)/gi;
  return join "\r", @res;
}
# msg_vias([$delim]) - return via lines from the message
sub msg_vias {
  my @res = $::text =~ /(?:^|\r)(\x01Via [^\r]*)/go;
  return join $_[0]||"\r", @res;
}
# msg_teerline - return the last line starting with '---' from the message
sub msg_teerline {
  my @res = $::text =~ /(?:^|\r)(---[^\r]*)/go;
  return @res ? $res[-1] : undef;
}
# msg_origin - return the last origin line from the message
sub msg_origin {
  my @res = $::text =~ /(?:^|\r)( \* Origin: [^\r]*)/go;
  return @res ? $res[-1] : undef;
}
# my basename function (works for dos and unix)
sub my_basename { return ($_[0] =~ /[^\\\/:]+$/o) ? $& : undef; }

}

1;

__END__
