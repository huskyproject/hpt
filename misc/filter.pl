# Local defines

sub msgdb    { return "c:\\fido\\hpt\\dupebase\\plduper.db"; }
sub pktdb    { return "c:\\fido\\hpt\\dupebase\\plduperpkt.db"; }
sub nodelist { return "c:\\fido\\nodelist"; }
sub nldb     { return "c:\\fido\\nodelist\\nodelist.db"; }
sub myaddr   { return "2:463/68"; }
sub msgbase  { return "c:\\fido\\msgbase\\"; }
sub netmail  { return msgbase . "netmail"; }
sub dupes    { return msgbase . "dupes"; }
sub faq      { return "c:\\fido\\itrack\\faq\\"; }

sub route94  { return "c:\\user\\gul\\work\\routing\\route.94"; }
sub sechubs  { return "c:\\fido\\nodelist\\2nd_hubs.463"; }
sub echol463 { return "c:\\user\\gul\\work\\echolist.463"; }

sub gupaddr  { return "gup\@lucky.net"; }
sub gupfrom  { return "gatemaster\@gul.kiev.ua"; }
sub gupstart { return "site happy.carrier.kiev.ua mypass\n"; }
sub echolist { return "c:\\user\\robots.zzz\\gate\\allnews.lst"; }

sub attr     { return qw(pvt crash read sent att fwd orphan k/s loc hld xx2 frq rrq cpt arq urq); }

sub maillists { return (
              "Staff",
              "Postmaster",
              "Admin",
              "Noc",
              "Hostmaster",
              "Cert",
              "Bugtraq",
              "Mutt-dev",
              "Registry"
              ); }

use DB_File;
use Fcntl ":flock";
use POSIX;

#use strict;

# predefined variables
#my($fromname, $toname, $fromaddr, $toaddr, $subject, $date, $text, $attr);
#my($secure, $pktname, $rc, $res, $area, $pktfrom, $addr, $from); 
#my($kill, $change, $flavour);

# My global variables
my(%nodelist, $nltied);
my(%pkt, $pkttied, %msg, $msgtied, $newnet, $newecho, @crc_32_tab);
my($processpktname, $pktkey, $pktval, %msgpkt, $curnodelist);

sub filter
{
# predefined variables:
# $fromname, $fromaddr, $toname,
# $toaddr (for netmail),
# $area (for echomail),
# $subject, $text, $pktfrom, $date, $attr
# $secure (defined if message from secure link)
# return "" or reason for moving to badArea
# set $kill for kill the message (not move to badArea)
# set $change to update $text, $subject, $fromaddr, $toaddr, $fromname, $toname
  my(@hf, @mypoints, @lines, $firstpath, $lastpath, @path, $origin);
  my(@lastpath, $net, @origin, $msgid, $msgidfrom, $approved, $path);
  my($key, $oldval, $fromboss, $toboss, $knownpoint, $fname, $time);
  my($oldtime, $oldpath, $oldpktfrom, $curtime, $dupetext, @roechoes);
  local(*F);
  @hf = qw(
    2:5020/113
    2:5020/32
    2:5020/140
    2:5020/50.40
    2:5020/50.140
    2:5020/140.1
    2:5020/35
    2:5020/35.1
    2:5000/13
    2:5000/44
    2:5020/293
    2:5020/1040
    2:5020/443
    2:5020/517
  );
  @mypoints = qw(
    2:463/68
    2:463/68.1  # Yutta
    2:463/68.2  # son
    2:463/68.3  # Bor Mal
    2:463/68.4  # Voronov
    2:463/68.5  # Ksyu
    2:463/68.8  # Sergey Iovov (/8.2)
    2:463/68.9  # Kussul
    2:463/68.11 # Brun
    2:463/68.12
    2:463/68.13 # Maxim Obukhov
    2:463/68.17 # Kalina
    2:463/68.18 # Andrew Ilchenko
    2:463/68.26 # Dmitry Rachkovsky
    2:463/68.27 # Andrey Zinin
    2:463/68.28 # Jean Kantoroff <jean@acalto.dial.intercom.it>
    2:463/68.32 # dk
    2:463/68.36 # Valentin Klinduh
    2:463/68.41 # Motus
    2:463/68.45 # Artem Kulakov  Sergei Shevyryov <megamed@wantree.com.au>
    2:463/68.47 # Parkhom
    2:463/68.50 # Rozhko
    2:463/68.62 # Victor Cheburkin /62
    2:463/68.67 # Alexey Suhoy /67
    2:463/68.92 # Andrey Ichtchenko
    2:463/68.108 # Vitaliy Oleynik
    2:463/68.114 # Валерий Дмитриевич и Людмила Сергеевна Кузнецовы
    2:463/68.128 # gate
    2:463/68.141 # Sergey Skorodinsky <ssv@i.am>
    2:463/68.163 # Den Dovgopoly
    2:463/68.196 # Tverskaya flat
    2:463/68.200 # Michael Bochkaryov
    2:463/68.586 # eug@lucky.net
    2:463/68.690 # Al Poduryan
    2:463/68.702 # Miroslav Narosetsky
  );
  @roechoes = qw(
    1072.Compnews
    BOCHAROFF.MUST.DIE
    BOCHAROFF.UNPLUGGED
    DIG.LINUX
    JET.PHRASES
    HUMOR.FILTERED
    GUITAR.SONGS.FILTERED
    OBEC.FILTERED
    PVT.EXLER.FILTERED
    RU.ANEKDOT.FILTERED
    RU.ANEKDOT.THE.BEST
    RU.AUTOSTOP.INFO
    RU.SPACE.NEWS
    RU.UFO.THEORY
    RU.WINDOWS.NT.NEWS
    SPB.HUMOR
    SPB.SYSOP.FILTERED
    SU.CRISIS.SITUATION
    SU.FORMULA1.INFO
    SU.OS2.FAQ
    SU.WIN95.NEWS
  );

  if (defined($area))
  {
    unless ($pktfrom =~ /^(2:463\/94(\.0)?|2:5020\/238(\.0)?)$/)
    { # from downlink
      foreach(@roechoes)
      {
        if ($area eq $_)
        {
          write_msg("none", $fromaddr, $toaddr, $fromname, $toname,
             "pvt sent read", $subject,
             "hpt> Posting to r/o echo $area\r" . $text,
             msgbase . "unsecure");
          $kill = 1;
          return "Posting to r/o echo $area";
        }
      }
    }
    $text =~ s/\r\n/\r/gs;
    @lines = split('\r', $text);
    $firstpath = $lastpath = $origin = $msgidfrom = "";
    @path = grep(/^\x01PATH: /, @lines);
    $firstpath = "2:$1" if $path[0] =~ /^\x01PATH: (\S+)/;
    $lastpath = pop(@path);
    $lastpath =~ s/^\x01PATH: //;
    @lastpath = split(/\s+/, $lastpath);
    foreach(@lastpath)
    { $net = $1 if m#^(\d+)/\d+$#;
      $_ = "$net/$_" if /^\d+$/;
      $lastpath = $_;
    }
    $lastpath = "2:$lastpath" if $lastpath;
    @lastpath = ();
    @origin = grep(/^ \* Origin: .*\(.*\)\s*$/, @lines);
    if (@origin)
    { $origin = pop(@origin);
      @origin = ();
      if ($origin =~ /\(([0-9:\/\.]+)(\@[A-Za-z0-9.\-]+)?\)\s*$/)
      { $origin = $1;
      } else
      { undef($origin);
        @origin = ();
      }
    }
    ($msgid) = grep(/^\x01MSGID:/, @lines);
    $msgidfrom = $1 if $msgid =~ /^\x01MSGID: ([0-9:\/\.])+(\@\S+)? /;
    if ($area eq "HUMOR.FILTERED")
    {
      $approved = 0;
      foreach (@hf)
      { $approved = 1 if $firstpath eq $_ || $origin eq $_ || $msgidfrom eq $_;
      }
      unless ($approved)
      {
        write_msg("none", $fromaddr, $toaddr, $fromname, $toname,
           "pvt sent read", $subject,
           "hpt> Unapproved message in $area\r" . $text,
           msgbase . "unsecure");
        $kill = 1;
        return "Unapproved message in $area";
      }
    }
    elsif ($area =~ /^PVT\.EXCH\./)
    { unless ($lastpath =~ m/^2:50/)
      { if ($origin =~ /^2:46/)
        {
          write_msg("none", $fromaddr, $toaddr, $fromname, $toname,
             "pvt sent read", $subject,
             "hpt> R46 is r/o in PVT.EXCH.*\r" . $text,
             msgbase . "unsecure");
          $kill = 1;
          return "R46 is r/o in PVT.EXCH.*";
        }
      }
    }
    elsif ($area eq "NET463.COORD")
    { if ($fromname eq "Routing Poster" && $fromaddr eq "2:463/94.0")
      { if (open(F, ">".route94))
        { foreach(grep(!/^(\x01|SEEN-BY:)/, @lines))
          { print F "$_\n";
          }
          close(F);
        }
      }
    }
    elsif ($area eq "N463.SYSOP" && $fromname eq "N463EC" && $fromaddr eq "2:463/11.0")
    { $fname = "";
      if ($subject eq "secondaries")
      { $fname = sechubs;
      } elsif ($subject eq "echolist")
      { $fname =  echol463;
      }
      if ($fname && open(F, ">$fname"))
      { foreach(grep(!/^(\x01|SEEN-BY:)/, @lines))
        { print F "$_\n";
        }
        close(F);
      }
    }
    # Dupecheck
    unless ($msgtied)
    {
      if (tie(%msg, 'DB_File', msgdb, O_RDWR|O_CREAT, 0644))
      { $msgtied = 1;
      } else
      { $newecho = 1;
        return "";
      }
    }
    if ($msgid)
    { $msgid =~ s/^\x01MSGID:\s*//;
      $msgid =~ tr/A-Z/a-z/;
    }
    else
    { $msgid = sprintf("C%s %08x", $fromaddr, crc32($date . join(' ',grep(!/^(\x01PATH|SEEN-BY):/,@lines))));
    }
    $key = "$area|$msgid|" . crc32($fromname . $toname . $subject);
    $path = "";
    foreach(grep(/^\x01PATH: /, @lines))
    { s/^\x01PATH:\s*//;
      $path .= " " if $path;
      $path .= $_;
    }
    $curtime = time();
    if (defined($msg{$key}) || defined($msgpkt{$key}))
    { # Dupe
      if (defined($msg{$key}))
      { $oldval = $msg{$key};
      } else
      { $oldval = $msgpkt{$key};
      }
      ($oldtime, $oldpath, $oldpktfrom) = split(/\|/, $oldval);
       $dupetext = <<EOF;
Pkt from: $pktfrom
Original pkt from: $oldpktfrom
Original PATH: $oldpath
$text
EOF
      write_msg($area, $fromaddr, "2:463/68", $fromname, $toname,
                "", $subject, $dupetext, dupes);
      $kill = 1;
      return "Dupe";
    }
    $msgpkt{$key} = "$curtime|$path|$pktfrom";
    $newecho = 1;
    return "";
  }
  # NetMail
  $fromaddr =~ s/\.0$//;
  $toaddr   =~ s/\.0$//;
  $fromboss = $fromaddr;
  $fromboss =~ s/\.\d+$//;
  $toboss   = $toaddr;
  $toboss   =~ s/\.\d+$//;
  if ($secure)
  { compileNL() unless $nltied;
    if ($nltied && !defined($nodelist{$toboss}))
    { bounce($fromname, $fromaddr, $toname, $toaddr, $date, $subject, $text,
             "Node $toboss mising in $curnodelist");
      $kill = 1;
      return "Node $toboss mising in $curnodelist";
    }
  }
  else
  { if (isattr("att", $attr))
    {
      write_msg("none", $fromaddr, $toaddr, $fromname, $toname,
         "pvt sent read", $subject,
         "hpt> FileAttach from unsecure link\r" . $text,
         msgbase . "unsecure");
      $kill = 1;
      return "FileAttach from unsecure link";
    }
    if ($fromaddr =~ /^(2:463\/68|2:46\/128)(\.\d+)?$/)
    {
      write_msg("none", $fromaddr, $toaddr, $fromname, $toname,
         "pvt sent read", $subject,
         "hpt> Unprotected message from my system\r" . $text,
         msgbase . "unsecure");
      $kill = 1;
      return "Unprotected message from my system";
    }
    compileNL() unless $nltied;
    if ($nltied && !defined($nodelist{$fromboss}))
    {
      write_msg("none", $fromaddr, $toaddr, $fromname, $toname,
         "pvt sent read", $subject,
         "hpt> Unprotected message from inlisted system\r" . $text,
         msgbase . "unsecure");
      $kill = 1;
      return "Unprotected message from unlisted system";
    }
    unless ($toaddr =~ /^(2:463\/68(\.\d+)?|2:46\/128(\.\d+)?|2:463\/59\.4|17:.*)$/)
    { bounce($fromname, $fromaddr, $toname, $toaddr, $date, $subject, $text,
             "Unprotected outgoing message");
      write_msg("none", $fromaddr, $toaddr, $fromname, $toname,
         "pvt sent read", $subject,
         "hpt> Unprotected outgoing message\r" . $text,
         msgbase . "unsecure");
      $kill = 1;
      return "Unprotected outgoing message";
    }
  }
  if ($toboss eq myaddr)
  {
    $knownpoint = 0;
    foreach(@mypoints)
    { $knownpoint = 1 if $_ eq $toaddr;
    }
    unless ($knownpoint)
    { bounce($fromname, $fromaddr, $toname, $toaddr, $date, $subject, $text,
             "Unknown point");
      write_msg("none", $fromaddr, $toaddr, $fromname, $toname,
         "pvt sent read", $subject,
         "hpt> Unknown point\r" . $text,
         msgbase . "itrack.bad");
      $kill = 1;
      return "Unknown point";
    }
  }
  if ($toaddr eq myaddr)
  { # check maillists
    foreach (maillists)
    { if ($toname eq $_)
      { s/ //;
        tr/A-Z/a-z/;
        s/^(........).*$/$1/;
        write_msg("none", $fromaddr, $toaddr, $fromname, $toname,
                  "pvt sent read", $subject, $text, msgbase . $_);
        $kill = 1;
        return "Maillist $toname";
      }
    }
    if ($toname =~ /^ping$/i)
    { 
      if (isattr("cpt", $attr))
      {
        write_msg("none", $fromaddr, $toaddr, $fromname, $toname,
           "pvt sent read", $subject,
           "hpt> Ping request with RRC\r" . $text,
           msgbase . "itrack.bad");
        $kill = 1;
        return "Ping request with RRC";
      }
      $text =~ s/\r\x01/\r\@/gs;
      $text =~ s/^\x01/\@/s;
      $time = localtime;
      $text = <<EOF;
   Hello $fromname.

Your ping-message received by my system at $time

Orignal message:

============================================================================
FROM:  $fromname	$fromaddr
TO  :  $toname		$toaddr
SUBJ:  $subject
DATE:  $date
============================================================================
$text
============================================================================
EOF
      write_msg("", myaddr, $fromaddr, "Crazy Mail Robot", $fromname,
                "pvt k/s loc cpt", "Ping Reply", $text, &netmail);
      $newnet = 1;
      $kill = 1;
      return "Ping from $fromaddr";
    }
    if ($toname =~ /^faqserver$/i)
    {
      if (isattr("cpt", $attr))
      {
        write_msg("none", $fromaddr, $toaddr, $fromname, $toname,
           "pvt sent read", $subject,
           "hpt> FaqServer request with RRC\r" . $text,
           msgbase . "itrack.bad");
        $kill = 1;
        return "FaqServer request with RRC";
      }
      faqserv($fromaddr, $fromname, $subject, $text);
      $newnet = 1;
      $kill = 1;
      return "Message to FaqServer";
    }
    if ($toname =~ /^(areafix|allfix|filefix)$/i)
    {
      if (isattr("cpt", $attr))
      {
        write_msg("none", $fromaddr, $toaddr, $fromname, $toname,
           "pvt sent read", $subject,
           "hpt> $toname request with RRC\r" . $text,
           msgbase . "itrack.bad");
        $kill = 1;
        return "$toname request with RRC";
      }
    }
    else
    {
      if (isattr("rrq", $attr) || isattr("arq", $attr))
      { receipt($fromaddr, $toaddr, $fromname, $toname, $subject, $date);
      }
      write_msg("none", $fromaddr, $toaddr, $fromname, $toname,
                "pvt sent read", $subject, $text, msgbase . "gul");
      $kill = 1;
      return "Message to gul";
    }
  }
  else
  {
    if (grep(/^\x01Via 2:463\/68(\.0)?(\@|\s)/, @lines) > 1)
    {
      write_msg("", $fromaddr, $toaddr, $fromname, $toname,
         "pvt sent read", $subject, "hpt> loop\r" . $text, msgbase . "loops");
      $kill = 1;
      return "Loop";
    }
    if (isattr("arq", $attr))
    { arqcpt($fromaddr, $toaddr, $fromname, $toname, $subject, $date, $attr);
    }
  }
  $newnet = 1;
  return "";
}

sub scan
{
# predefined variables:
# $area, $fromname, $fromaddr, $toname,
# $toaddr (for netmail),
# $subject, $text, $date, $attr
# return "" or reason for dont packing to downlinks
# set $change to update $text, $subject, $fromaddr, $toaddr, $fromname, $toname
  my ($toboss, $addr, $msgid, $key);
  my ($oldtime, $oldpath, $oldpktfrom, $dupetext);

  if ($toaddr eq "")
  { # echomail
    unless ($msgtied)
    {
      tie(%msg, 'DB_File', msgdb, O_RDWR|O_CREAT, 0644) || return "";
      $msgtied = 1;
    }
    ($msgid) = grep(/^\x01MSGID:/, split('\r', $text));
    if ($msgid)
    { $msgid =~ s/^\x01MSGID:\s*//;
      $msgid =~ tr/A-Z/a-z/;
    }
    else
    { $msgid = sprintf("C%s %08x", $fromaddr, crc32($date . join(' ',grep(!/^(\x01PATH|SEEN-BY):/,split('\r', $text)))));
    }
    $key = "$area|$msgid|" . crc32($fromname . $toname . $subject);
    if (defined($msg{$key}))
    { # Dupe
      ($oldtime, $oldpath, $oldpktfrom) = split(/\|/, $msg{$key});
      $dupetext = <<EOF;
Pkt from: local
Original pkt from: $oldpktfrom
Original PATH: $oldpath
$text
EOF
      write_msg($area, $fromaddr, "2:463/68", $fromname, $toname,
                "", $subject, $dupetext, dupes);
      return "Dupe";
    }
    $msg{$key} = time() . "|local|local";
    return "";
  }
  $toboss   = $toaddr;
  $toboss   =~ s/\.\d+$//;
  if ($text =~ /^hpt> [^\r]+\r/)
  { $text = $';
    $change = 1;
  }
  compileNL() unless $nltied;
  if ($nltied && !defined($nodelist{$toboss}))
  {
    bounce($fromname, $fromaddr, $toname, $toaddr, $date, $subject, $text,
           "Node $toboss mising in $curnodelist");
    return "Node $toboss mising in $curnodelist";
  }
  if ($fromaddr eq myaddr &&
      !isattr("cpt", $attr) &&
      $area =~ /^netmail$/i &&
      $fromname !~ /areafix|crazy mail robot|allfix|ping|uucp/i)
  { write_msg("none", $fromaddr, $toaddr, $fromname, $toname,
              "pvt sent read", $subject, $text, msgbase . "i_sent");
  }
  if ($toaddr eq myaddr)
  { if ($toname =~ /^faqserver$/i)
    {
      faqserv($fromaddr, $fromname, $subject, $text);
      $newnet = 1;
      return "Message to FaqServer";
    }
    unless ($toname =~ /^(areafix|allfix|filefix)$/i)
    { write_msg("none", $fromaddr, $toaddr, $fromname, $toname,
                "pvt sent read", $subject, $text, msgbase . "gul");
      return "Message to gul";
    }
  }
  elsif ($toaddr =~ /^(2:46\/128(\.0)?|2:463\/68\.128)$/)
  { if ($toname =~ /^areafix$/i && $subject =~ /^uucp$/i && $fromaddr =~ /^2:463\/68(\.0)?$/)
    { return "GateAreafix: " . gateareafix($text);
    }
  }
  $addr = $area;
  $addr =~ tr/A-Z/a-z/;
  foreach(maillists)
  { s/ //g;
    tr/A-Z/a-z/;
    if ($addr eq $_)
    { $toaddr = "2:46/128";
      $toname = "$_\@lucky.net";
      $text =~ s#^((?:.*\r)?)\x01INTL\s+\S+\s+(\S+)\s*\r#$1\x01INTL 2:46/128 $2\r#s;
      $text =~ s/^((?:.*\r)?)\x01TOPT[^\r]+\r//s;
      $change = 1;
      return "";
    }
  }
  return "";
}

sub route
{
# $addr = dest addr
# $from = orig addr
# $text = message text
# $attr = message attributes
# set $flavour to hold|normal|crash|direct|immediate
# return route addr or "" for default routing

  return _route($toaddr, $attr);
}

sub _route
{
  my ($toaddr, $attr) = @_;

  my @routemail = (
"crash  17:1800/94  17:.*",
"hold   2:46/128    (2:46/128|2:463/68.128)",
"hold   2:999/999   2:46/128\.",
"hold   noroute     2:463/68(\.\d+)?",
"hold   2:463/68.8  2:463/8\.2",
"hold   2:463/68.17 2:463/62\.17",
"crash  2:463/168   2:463/168(\.\d+)?",
"normal 2:463/666   2:(463/666|46/200)(\.\d+)?",
"crash  2:463/94    [123456]:.*",
"hold   2:999/999   .*"
);
  my @routefile = (
"crash  2:463/94    2:(463/83|463/940(\.\d+)?|462/95|4653/10|4643/5",
"crash  2:463/94    2:463/11(\.11)?",
"normal 2:463/666   2:(463/666(\.\d+)?|2:46/200)",
"crash  2:463/94    2:(46/0|465/50|465/70)",
"hold   noroute     .*"
);
  my (@route, $dest, $patt, $boss);

  compileNL() unless $nltied;

  if (isattr("att", $attr))
  { @route = @routefile;
  } else
  { @route = @routemail;
  }
  $addr =~ s/\.0$//;
  foreach (@route)
  { ($flavour, $dest, $patt) = split(/\s+/, $_);
    $boss = $addr;
    $boss =~ s/\..*//;
    if ($patt =~ /^hub(.*)/i)
    { $_ = $1;
      $dest = "";
      $dest = $1 if $nodelist{$boss} =~ /,(.*)/;
      $patt = ".*" if $_ eq $dest;
    } elsif ($patt =~ /^reg(.*)/i)
    { $_ = $1;
      $dest = "";
      $dest = $1 if $nodelist{$boss} =~ /^(.*),/;
      $patt = ".*" if $_ eq $dest;
    }
    if ($addr =~ /^$patt$/)
    { if ($dest eq "noroute")
      { $dest = $addr;
      } elsif ($dest eq "boss")
      { $dest = $boss;
      } elsif ($dest eq "host")
      { $dest = $addr;
        $dest =~ s#/.*#/0#;
      } elsif ($dest eq "hub")
      { $dest = $boss;
        $dest = $1 if $nodelist{$boss} =~ /,(.*)/;
      }
      return $dest;
    }
  }
  return "";
}

sub hpt_exit
{
  my($flags);
  local(*F);
  untie %nodelist if $nltied;
  untie %pkt if $pkttied;
  untie %msg if $msgtied;
  $nltied = $pkttied = $msgtied = 0;
  $flags = $ENV{"FLAGS"};
  close(F) if $newnet && open(F, ">$flags/wasnet.now");
  close(F) if $newecho && open(F, ">$flags/wasecho.now");
}

sub process_pkt
{
# $pktname - name of pkt
# $secure  - defined for secure pkt
# return non-empty string for rejecting pkt (don't process, rename to *.dup)
  my($a, $crc, $a, $mtime, $size, $pktstart);
  local(*F);
  $processpktname = "";
  %msgpkt = ();
  unless ($pkttied)
  {
    if (tie(%pkt, 'DB_File', pktdb, O_RDWR|O_CREAT, 0644))
    { $pkttied = 1;
    } else
    { return "";
    }
  }
  ($a,$a,$a,$a,$a,$a,$a,$size,$a,$mtime) = stat($pktname);
  open(F, "<$pktname") || return;
  read(F, $pktstart, 58+178); # sizeof(pkthdr) + sizeof(msghdr) (max msghdr)
  close(F);
  $crc = crc32($pktstart);
  $pktname =~ s/^.*[\/\\]//; # basename
  $pktname =~ tr/A-Z/a-z/;
  $pktkey = sprintf("%s|%u|%08x|%08x", $pktname, $size, $mtime, $crc);
  $pktval = time();
  $processpktname = $pktname;
  return "Duplicate $pktname" if defined($pkt{$pktkey});
  return "";
}

sub pkt_done
{
# $pktname - name of pkt
# $rc      - exit code (0 - OK)
# $res     - reason (text line)
# 0 - OK ($res undefined)
# 1 - Security violation
# 2 - Can't open pkt
# 3 - Bad pkt format
# 4 - Not to us
# 5 - Msg tossing problem
  my ($key, $val, $curtime, $sec, $min, $hour, $mday, $msgtime);
  return if defined($res) || !defined($pktkey) || !$pkttied;
  $pktname =~ s/^.*[\/\\]//; # basename
  $pktname =~ tr/A-Z/a-z/;
  return if $pktname ne $processpktname && $pktname ne "";
  $pkt{$pktkey} = $pktval;
  ($sec,$min,$hour,$mday) = localtime();
  if ($mday ne $pkt{"lastpurge"})
  { print "Purging pkt dupebase...";
    $curtime = time();
    while (($key, $val) = each %pkt)
    { delete($pkt{$key}) if $curtime-$val>14*24*3600;
    }
    $pkt{"lastpurge"} = $mday;
    print " Done\n";
  }
  $processpktname = "";
  return if !$msgtied;
  while (($key, $val) = each %msgpkt)
  { $msg{$key} = $val;
    delete $msgpkt{$key};
  }
  %msgpkt = ();
  if ($mday ne $msg{"lastpurge"})
  { print "Purging msg dupebase...";
    $curtime = time();
    while (($key, $val) = each %msg)
    { ($msgtime) = split(/\|/, $val);
      delete($msg{$key}) if $curtime-$msgtime>14*24*3600;
    }
    $msg{"lastpurge"} = $mday;
    print " Done\n";
  }
}

sub after_unpack
{
}

sub before_pack
{
}


# ========================================================================
#                        local functions
# ========================================================================

sub compileNL
{
  my(@nlfiles, $a, $mtime, $ctime, $curtime, $curmtime, $curctime);
  my($zone, $region, $net, $hub, $node, $flag);
  local(*F);
  opendir(F, nodelist) || return;
  @nlfiles = grep(/^nodelist\.\d\d\d$/i, readdir(F));
  closedir(F);
  return unless @nlfiles;
  $curnodelist = pop(@nlfiles);
  ($a,$a,$a,$a,$a,$a,$a,$a,$a,$curmtime,$curctime) = stat(nodelist . "/$curnodelist");
  foreach(@nlfiles)
  { ($a,$a,$a,$a,$a,$a,$a,$a,$a,$mtime,$ctime) = stat(nodelist . "/$_");
    if ($mtime > $curmtime)
    { $curmtime = $mtime;
      $curctime = $ctime;
      $curnodelist = $_;
    }
  }
  ($a,$a,$a,$a,$a,$a,$a,$a,$a,$mtime,$ctime) = stat(nldb);
  if (!defined($mtime) || $mtime < $curmtime)
  {
    unlink(nldb);
    tie(%nodelist, 'DB_File', nldb, O_RDWR|O_CREAT, 0644) || return;
    unless (open(F, "<".nodelist."/$curnodelist"))
    { untie(%nodelist);
      return;
    }
    $zone = $region = $net = $hub = "";
    print "Compiling nodelist...";
    while (<F>)
    { chomp();
      next if /^(;.*)?$/;
      ($flag,$node) = split(/,/);
      if ($flag eq "Zone")
      { $zone = $net = $node;
        $node = 0;
        $region = $hub = "$zone:$net/$node";
      } elsif ($flag eq "Region")
      { $net = $node;
        $node = 0;
        $region = $hub = "$zone:$net/$node";
      } elsif ($flag eq "Host")
      { $net = $node;
        $node = 0;
        $hub = "$zone:$net/$node";
      } elsif ($flag eq "Hub")
      { $hub = "$zone:$net/$node";
      }
      $nodelist{"$zone:$net/$node"}="$region,$hub";
    }
    close(F);
    untie(%nodelist);
    print "Done.\n";
  }
  tie(%nodelist, 'DB_File', nldb, O_RDONLY) && ($nltied=1);
  return;
}

sub bounce
{
  my($fromname, $fromaddr, $toname, $toaddr, $date, $subject, $text, $reason) = @_;
  my($bouncetext);
  local(*F);

  $text =~ tr/\r/\n/;
  $text =~ s/\n\x01/\n\@/gs;
  $text =~ s/^\x01/\@/s;
  $bouncetext = <<EOF;
   Hello $fromname.

$reason
Therefore I must return this message to you.

                 Lucky Carrier,
                                     Pavel Gulchouck
                                     gul\@gul.kiev.ua

Orignal message:

============================================================================
FROM:  $fromname	$fromaddr
TO  :  $toname		$toaddr
SUBJ:  $subject
DATE:  $date
============================================================================
$text
============================================================================
EOF
  write_msg("", myaddr, $fromaddr, "Crazy Mail Robot", $fromname,
            "pvt k/s loc cpt", "Unable to delivery", $bouncetext, &netmail);
  $newnet = 1;
  return $reason;
}

sub crc32
{
  my($str) = @_;
  my($i, $len, $crc);
  $str =~ s/\s\s+/ /gs;
  unless (@crc_32_tab)
  {
    @crc_32_tab = ( # CRC polynomial 0xedb88320
0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
    );
  }

  $crc = 0xFFFFFFFF;
  $len = length($str);
  for ($i=0; $i<$len; $i++)
  { $crc = $crc_32_tab[($crc ^ substr($str, $i, 1)) & 0xff] ^ ($crc >> 8);
  }
  return $crc;
}

sub isattr
{
  my($sattr, $attr) = @_;
  my($i, $b);
  for ($i=0, $b=1; $i<&attr; $i++)
  { return ($attr & $b) ? 1 : 0 if $sattr eq (&attr)[$i];
    $b *= 2;
  }
  return "";
}

sub write_msg
{
  # netmail if $at defined
  my($area, $af, $at, $nf, $nt, $attr, $subj, $text, $dir) = @_;
  my($maxmsg, $i, $b, $battr, $msgtext, $flags, $msghdr, $kludges, $date);
  my($tzone, $tnet, $tnode, $tpoint, $fzone, $fnet, $fnode, $fpoint);
  local(*F);
  $text =~ tr/\n/\r/;
  $text .= "\r" unless $text =~ /\r$/s;
  $maxmsg = 0;
  if (opendir(F, $dir))
  { while ($_ = readdir(F))
    { next unless /^(\d+)\.msg$/i;
      $maxmsg = $1 if $maxmsg < $1;
    }
    closedir(F);
  }
  while (1)
  { $maxmsg++;
    last if sysopen(F, "$dir/$maxmsg.msg", &O_RDWR|&O_CREAT|&O_EXCL, 0640);
    if ($! != &EEXIST)
    { return "Can't create $dir/$maxmsg.msg: $!";
    }
  }
  unless (flock(F, &LOCK_EX))
  { close(F);
    return "Can't flock $dir/maxmsg.msg: $!";
  }
  # put header
  $af .= ".0" unless $af =~ /\.\d+$/;
  if ($at)
  { $at .= ".0" unless $at =~ /\.\d+$/;
  }
  ($fzone, $fnet, $fnode, $fpoint) = ($1, $2, $3, $4) if $af =~ /^(\d+):(\d+)\/(\d+)\.(\d+)$/;
  ($tzone, $tnet, $tnode, $tpoint) = ($1, $2, $3, $4) if $at =~ /^(\d+):(\d+)\/(\d+)\.(\d+)$/;
  $battr = 0;
  $flags = "";
  foreach (split(/\s+/, $attr))
  { for ($i=0, $b=1; $i<&attr; $i++)
    { if ($_ eq (&attr)[$i])
      { $battr |= $b;
        last;
      }
      $b *= 2;
    }
    $flags .= " $_" if $i == &attr;
  }
  $flags =~ tr/a-z/A-Z/;
  $date = strftime "%d %b %y  %H:%M:%S", localtime; 
  $msghdr = pack("a36a36a72a20v13", $nf, $nt, $subj, $date,
                 0, $tnode, $fnode, 0, $fnet, $tnet, $tzone, $fzone,
                 $tpoint, $fpoint, 0, $battr, 0);
  $kludges = "";
  if ($area)
  { $kludges .= "AREA:$area\r" unless $area eq "none";
  }
  else
  { # netmail
    $kludges = "\x01INTL $tzone:$tnet/$tnode $fzone:$fnet/$fnode\r"
      unless $text =~ /^(.*\r)?\x01INTL /is;
    $kludges .= "\x01FMPT $fpoint\r"
      unless $fpoint == 0 || $text =~ /^(.*\r)?\x01FMPT:? /is;
    $kludges .= "\x01TOPT $tpoint\r"
      unless $tpoint == 0 || $text =~ /^(.*\r)?\x01TOPT:? /is;
  }
  $kludges .= "\x01FLAGS$flags\r"
    unless $flags eq "" || $text =~ /^(.*\r)?\x01FLAGS:? /;
  unless ($area || $text =~ /^(.*\r)?\x01MSGID:/is)
  { $af =~ s/\.0$//;
    $kludges .= sprintf("\x01MSGID: $af %08x\r", time());
  }
  syswrite(F, $msghdr . $kludges . $text . "\x00");
  flock(F, &LOCK_UN);
  close(F);
  return "";
}

sub faqserv
{
  my($fromaddr, $fromname, $subject, $text) = @_;
  my($size, $fsize, @lines, $reply, $correct, $skip, $topic, $a);
  local(*F);
  @lines = split('\r', $text);
  if ($subject =~ /\S/)
  { @lines = unshift(@lines, "Subject: $subject");
  } else
  { $subject = "";
  }
  $reply = "";
  $skip = "";
  $size = 0;
  foreach (@lines)
  {
    $reply .= "> $_\r";
    next if $skip;
    $_ = $subject if $subject;
    $subject = "";
    s/^\s*%?(\S+).*/$1/;
    s/^(........).*$/$1/;
    tr/A-Z/a-z/;
    if (/^(--.*|quit|exit)$/)
    { $reply .= "Rest skipped\r";
      $skip = 1;
      next;
    }
    ($a,$a,$a,$a,$a,$a,$a,$fsize) = stat(faq . "$_.faq");
    if (($size += $fsize) > 102400)
    { $reply .= "Size limit riched, rest skipped\r";
      $skip = 1;
      next;
    }
    if (open(F, "<" . faq . "$_.faq"))
    { read(F, $topic, $fsize);
      write_msg("", myaddr, $fromaddr, "FaqServer", $fromname,
                "pvt loc k/s cpt", "Topic $_", $topic, netmail);
      close(F);
      $correct = 1;
    }
    else
    {
      $reply .= "Topic $_ not found\r";
    }
  }
  unless($correct)
  {
    $reply .= "No valid commands found, help sent\r";
    if (open(F, "<" . faq . "help.faq"))
    { read(F, $topic, $fsize);
      write_msg("", myaddr, $fromaddr, "FaqServer", $fromname,
                "pvt loc k/s cpt", "Help response", $topic, netmail);
      close(F);
    }
  }
  write_msg("", myaddr, $fromaddr, "FaqServer", $fromname,
            "pvt loc k/s cpt", "FaqServer reply", $reply, netmail);
}

sub gateareafix
{
  my($text) = @_;
  my ($offs, %offset, %relcom, $gupmsg);
  local(*F);

  $text =~ tr/\r/\n/;
  open(F, echolist) || return "Can't open " . echolist . ": $!";
  $offs = 0;
  while (<F>)
  { next unless /^.onference\s+(\S+)\s+(\S+)\s*$/;
    $relcom{$1} = $2;
    $offset{$1} = $2;
    $offs = tell(F);
  }
  $gupmsg = "From: ".gupfrom."\nTo: ".gupaddr."\n\n".gupstart."\n";
  foreach (split('\n', $text))
  {
    last if /^---/;
    next unless /^([+-])(\S+)/;
    next if !defined($relcom{$1});
    $gupmsg .= sprintf("%s %s\n", ($1 eq "+" ? "include" : "exclude"), $relcom{$2});
    seek(F, $offset{$2}, 0);
    print F ($1 eq "+" ? "c" : "C");
  }
  close(F);
  open(F, "|sendmail ".gupaddr) || return "Can't run sendmail: $!";
  print F $gupmsg;
  return "";
}

sub arqcpt
{
  my($fromaddr, $toaddr, $fromname, $toname, $subject, $date, $attr) = @_;
  my($text, $route);
  $route = _route($toaddr, $attr);
  $route = "internet gate" if $route eq "2:46/128";
  $text = <<EOF;
    Hello $fromname!

Your message with ARQ passed to $route through my station.

Original message header:
=============================================================
 From:    $fromname          $fromaddr
 To:      $toname            $toaddr
 Subject: $subject
 Date:    $date
=============================================================

                  Lucky carrier,
                         Pavel Gulchouck (and my mail robot;)
EOF
  write_msg("", myaddr, $fromaddr, "Crazy Mail Robot", $fromname,
            "pvt k/s loc cpt", "Audit Receipt Response", $text, netmail);
  $newnet = 1;
}

sub receipt
{
  my($fromaddr, $toaddr, $fromname, $toname, $subject, $date) = @_;
  my($text);
  $text = <<EOF;
    Hello $fromname!

Your message to $toname successfully delivered.

Original message header:
=============================================================
 From:    $fromname          $fromaddr
 To:      $toname            $toaddr
 Subject: $subject
 Date:    $date
=============================================================

                  Lucky carrier,
                         Pavel Gulchouck (and my mail robot;)
EOF
  write_msg("", myaddr, $fromaddr, "Crazy Mail Robot", $fromname,
            "pvt k/s loc cpt", "Return Receipt Response", $text, netmail);
  $newnet = 1;
}
