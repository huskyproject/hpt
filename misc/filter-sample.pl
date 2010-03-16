# Local defines

sub msgdb    { return "c:\\fido\\hpt\\dupebase\\plduper.db"; }
sub pktdb    { return "c:\\fido\\hpt\\dupebase\\plduperpkt.db"; }
sub nldb     { return "c:\\fido\\nodelist\\nodelist.db"; }
sub faq      { return "c:\\fido\\itrack\\faq\\"; }

sub route94  { return "c:\\user\\gul\\work\\routing\\route.94"; }
sub sechubs  { return "c:\\fido\\nodelist\\2nd_hubs.463"; }
sub echol463 { return "c:\\user\\gul\\work\\echolist.463"; }
sub listdir  { return "c:\\fido\\hpt\\"; }
sub listname { return "5020_238.avl"  if $_[0] eq "2:5020/238";
               return "5020_1381.avl" if $_[0] eq "2:5020/1381";
               return "94.avl"        if $_[0] eq "2:463/94";
               return "58.avl"        if $_[0] eq "2:463/58";
               return "";
             }

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
my($processpktname, $pktkey, $pktval, %msgpkt, $curnodelist, @areas);

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
  my($key, $oldval, $fromboss, $toboss, $knownpoint, $fname, $time, @myaddr);
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

  @myaddr = &myaddr;
  if (defined($area))
  {
    unless ($pktfrom =~ /^(2:463\/94(\.0)?|2:5020\/238(\.0)?)$/)
    { # from downlink
      foreach(@roechoes)
      {
        if ($area eq $_)
        {
          putMsgInArea("UNSECURE", $fromname, $toname, $fromaddr, $toaddr,
             $subject, $date, "pvt sent read",
             "hpt> Posting to r/o echo $area\r" . $text, 0);
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
        putMsgInArea("UNSECURE", $fromname, $toname, $fromaddr, $toaddr,
           $subject, $date, "pvt sent read",
           "hpt> Unapproved message in $area\r" . $text, 0);
        $kill = 1;
        return "Unapproved message in $area";
      }
    }
    elsif ($area =~ /^PVT\.EXCH\./)
    { unless ($lastpath =~ m/^2:50/)
      { if ($origin =~ /^2:46/)
        {
          putMsgInArea("UNSECURE", $fromname, $toname, $fromaddr, $toaddr,
             $subject, $date, "pvt sent read",
             "hpt> R46 is r/o in PVT.EXCH.*\r" . $text, 0);
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
      putMsgInArea("DUPES", $fromname, $toname, $fromaddr, "",
                   $subject, $date, "pvt sent read", $dupetext, 0);
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
      putMsgInArea("UNSECURE", $fromname, $toname, $fromaddr, $toaddr,
         $subject, $date, "pvt sent read",
         "hpt> FileAttach from unsecure link\r" . $text, 0);
      $kill = 1;
      return "FileAttach from unsecure link";
    }
    if ($fromaddr =~ /^(2:463\/68|2:46\/128)(\.\d+)?$/)
    {
      putMsgInArea("UNSECURE", $fromname, $toname, $fromaddr, $toaddr,
         $subject, $date, "pvt sent read",
         "hpt> Unprotected message from my system\r" . $text, 0);
      $kill = 1;
      return "Unprotected message from my system";
    }
    compileNL() unless $nltied;
    if ($nltied && !defined($nodelist{$fromboss}))
    {
      putMsgInArea("UNSECURE", $fromname, $toname, $fromaddr, $toaddr,
         $subject, $date, "pvt sent read",
         "hpt> Unprotected message from inlisted system\r" . $text, 0);
      $kill = 1;
      return "Unprotected message from unlisted system";
    }
    unless ($toaddr =~ /^(2:463\/68(\.\d+)?|2:46\/128(\.\d+)?|2:463\/59\.4|17:.*)$/)
    { bounce($fromname, $fromaddr, $toname, $toaddr, $date, $subject, $text,
             "Unprotected outgoing message");
      putMsgInArea("UNSECURE", $fromname, $toname, $fromaddr, $toaddr,
         $subject, $date, "pvt sent read",
         "hpt> Unprotected outgoing message\r" . $text, 0);
      $kill = 1;
      return "Unprotected outgoing message";
    }
  }
  if ($toboss eq $myaddr[0])
  {
    $knownpoint = 0;
    foreach(@mypoints)
    { $knownpoint = 1 if $_ eq $toaddr;
    }
    unless ($knownpoint)
    { bounce($fromname, $fromaddr, $toname, $toaddr, $date, $subject, $text,
             "Unknown point");
      putMsgInArea("BADMAIL", $fromname, $toname, $fromaddr, $toaddr,
         $subject, $date, "pvt sent read",
         "hpt> Unknown point\r" . $text, 0);
      $kill = 1;
      return "Unknown point";
    }
  }
  if ($toaddr eq $myaddr[0])
  { # check maillists
    foreach (maillists)
    { if ($toname eq $_)
      { s/ //;
        tr/A-Z/a-z/;
        s/^(........).*$/$1/;
        putMsgInArea($_, $fromname, $toname, $fromaddr, $toaddr,
                  $subject, $date, "pvt sent read", $text, 0);
        $kill = 1;
        return "Maillist $toname";
      }
    }
    if ($toname =~ /^ping$/i)
    { 
      if (isattr("cpt", $attr))
      {
        putMsgInArea("BADMAIL", $fromname, $toname, $fromaddr, $toaddr,
           $subject, $date, "pvt sent read",
           "hpt> Ping request with RRC\r" . $text, 0);
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
      putMsgInArea("", "Crazy Mail Robot", $fromname, "", $fromaddr,
                "Ping Reply", "", "pvt k/s loc cpt", $text, 1);
      $newnet = 1;
      $kill = 1;
      return "Ping from $fromaddr";
    }
    if ($toname =~ /^faqserver$/i)
    {
      if (isattr("cpt", $attr))
      {
        putMsgInArea("BADMAIL", $fromname, $toname, $fromaddr, $toaddr,
           $subject, $date, "pvt sent read",
           "hpt> FaqServer request with RRC\r" . $text, 0);
        $kill = 1;
        return "FaqServer request with RRC";
      }
      faqserv($fromaddr, $fromname, $subject, $text);
      $newnet = 1;
      $kill = 1;
      return "Message to FaqServer";
    }
    if (($fromname =~ /^(areafix|gecho|crashecho|areafix daemon|sqafix)$/i ||
         $fromname =~ /echo manager/) &&
        listname($fromaddr) ne "" &&
        ($subject =~ /^(List request|List of areas available|List of available areas|AreaFix list of areas|AreaFix response|[Aa]reafix reply: (list request|available areas))/ ||
         $subject =~ /^Your Areafix Request$/ && $text =~ /Areas available to|\001SPLITTED:/s && $text =~ /\r\n?      \S+\r/s ||
         $subject =~ /^Remote request operation report/ && $text =~ /areas available for|continued from the previous message/s ||
         $subject =~ /Reply from Parma Tosser Echo Manager, part/))
    {
      if ($subject eq "AreaFix response" && $text =~ /\r\n?%LIST.*\r\n?--- CrashEcho's AreaFix/s)
      { $kill = 1;
        return "CrashEcho's areafix response";
      }
      if (@areas)
      { if ($areas[0] ne $fromaddr)
        { putlist();
          @areas=($fromaddr);
        }
      }
      else
      { @areas=($fromaddr);
      }
      foreach (split(/\s*\r\n?/, $text))
      {
        next if /^(\x01|SEEN-BY:)/;
        if ($subject =~ /^AreaFix list of areas/) # CrashEcho
        { if (/^ {15,}(\S(?:.*\S)?)\s+(?:\?|\d+)\s*$/ && $areas[1])
          { $areas[@areas-1] .= " $1";
            next;
          }
        }
        elsif (/^ {15,}(\S.*)$/ && $areas[1] && $subject =~ /Parma Tosser/)
        { $areas[@areas-1] .= " $1"; # or "$1", without space?
          next;
        }
        elsif (/^ {15,}(\S.*)$/ && $areas[1])
        { $areas[@areas-1] .= " $1";
          next;
        }
        if ($subject =~ /^List request/)
        { # FastEcho
          next unless /^[\* ] (\S+)(?:(?: \.*)? (\S.*))?\s*$/;
          push (@areas, "$1 $2");
          next;
        }
        if ($subject =~ /^List of areas available/)
        { # FastEcho
          next unless /^([^() \*\'\-\[][^() *]*)(?: \.+ (\S.*))?\s*$/;
          push (@areas, "$1 $2");
          next;
        }
        if ($subject =~ /^List of available areas/)
        { # GEcho
          next unless /^[+ ](\S+)(?: +(\S.*))?\s*$/;
          next if /^ '[+-]'/;
          push (@areas, "$1 $2");
          next;
        }
        if ($subject =~ /^AreaFix list of areas/)
        { # CrashEcho
          next if /^ Group:/;
          next unless /^ (\S+)(?:\s+(\S(?:.*\S)?)?\s+(?:\?|\d+))?\s*$/;
          push (@areas, "$1 $2");
          next;
        }
        if ($subject =~ /^Your Areafix Request/)
        { # Fidogate
          next unless /^[ *] [ R]   (\S+)\s*$/;
          push (@areas, $1);
          next;
        }
        if ($subject =~ /^[Aa]reafix reply: list request/)
        { # hpt
          next unless /^[* ][R ]? (\S+)(?: \.* (\S.*))?\s*$/;
          push (@areas, "$1 $2");
          next;
        }
        if ($subject =~ /^[Aa]reafix reply: available areas/)
        { # hpt
          next unless /^ (\S+)(?: \.* (\S.*))?\s*$/;
          push (@areas, "$1 $2");
          next;
        }
        if ($subject =~ /^Remote request operation report/)
        { # SqaFix
          next unless /^(\S+) \.+ (?:Unlinked|Active  )   \[\S\](?: (\S.*\S))?\s*$/;
          push (@areas, "$1 $2");
        }
        if ($subject =~ /Parma Tosser/)
        { # Parma Tosser
          next if /^(Splitted by|--- |UpLink |Available areas|List of|Hello |Parma )/;
          if (/^([A-Za-z\.&\$0-9!'_\+\-]+)(?:(?: \.+)?\s+(\:Unlinked|Lined)\s+\[.\] (.*))?$/)
          { push(@areas, "$1 $2");
          }
        }
      }
      $kill=1;
      return "List reply";
    }
    if ($toname =~ /^(areafix|allfix|filefix)$/i)
    {
      if (isattr("cpt", $attr))
      {
        putMsgInArea("BADMAIL", $fromname, $toname, $fromaddr, $toaddr,
           $subject, $date, "pvt sent read",
           "hpt> $toname request with RRC\r" . $text, 0) ||
        ($kill = 1);
        return "$toname request with RRC";
      }
    }
    else
    {
      if (isattr("rrq", $attr) || isattr("arq", $attr))
      { receipt($fromaddr, $toaddr, $fromname, $toname, $subject, $date);
      }
      putMsgInArea("GUL", $fromname, $toname, $fromaddr, $toaddr,
                $subject, $date, "pvt sent read", $subject, $text, 0) ||
      ($kill = 1);
      return "Message to gul";
    }
  }
  else
  { # Transit message
    # Dupe- and loop- check
    opendupe();
    if ($msgtied)
    {
      ($msgid) = grep(/^\x01MSGID:/, @lines);
      if ($msgid)
      { $msgid =~ s/^\x01MSGID:\s*//;
        $msgid =~ tr/A-Z/a-z/;
      }
      else
      { $msgid = sprintf("C%s %08x", $fromaddr, crc32($date . join(' ',grep(!/^(\x01(Via|Recd|Forwarded))(:|\s)/,@lines))));
      }
      $key = sprintf("NETMAIL|%s|%s|%08x", $msgid, $toaddr, crc32($fromname . $toname . $subject));
      $path = $lastpath = "";
      foreach(grep(/^\x01(Via|Recd|Forwarded):?\s/, @lines))
      { next unless m#(\d+:\d+/\d+(?:\.\d+)?)(\@|\s)#;
        next if $lastpath eq $1;
        $lastpath = $1;
        $path .= " " if $path;
        $path .= $1;
      }
      $curtime = time();
      if ($oldval=checkdupe($key))
      { # Dupe or Loop
        $dupetext = $text;
        $dupetext =~ s/\r\n?/\n/gs;
        ($oldtime, $oldpath, $oldpktfrom) = split(/\|/, $oldval);
        $oldtime = localtime($oldtime);
        if ($path eq $oldpath && $oldpktfrom eq $pktfrom)
        { # Dupe
           $dupetext = <<EOF;
Pkt from: $pktfrom
Original msg arrived: $oldtime
$dupetext
EOF
          putMsgInArea("NETMAILDUPES", $fromname, $toname, $fromaddr, "",
                       $subject, $date, "pvt sent read", $dupetext, 0);
          $kill = 1;
          return "Dupe";
        } else
        { # Loop
          putMsgInArea("LOOPS", $fromname, $toname, $fromaddr, $toaddr,
                       $subject, $date, "pvt sent read",
                       "hpt> loop\r" . $text, 0);
          $kill = 1;
          return "Loop";
        }
      }
      adddupe($key, "$curtime|$path|$pktfrom");
    }
    if (_route($toaddr, $attr, $text) eq $pktfrom)
    { # Route to pktfrom-addr -- ping-pong
      putMsgInArea("LOOPS", $fromname, $toname, $fromaddr, $toaddr,
                   $subject, $date, "pvt sent read",
                   "hpt> ping-pong with $pktfrom\r" . $text, 0);
      $kill = 1;
      return "Loop";
    }
    if (isattr("arq", $attr))
    { arqcpt($fromaddr, $toaddr, $fromname, $toname, $subject, $date, $attr, $text);
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
      putMsgInArea("DUPES", $fromname, $toname, $fromaddr, "",
                $subject, $date, "pvt sent read", $dupetext, 0);
      return "Dupe";
    }
    $msg{$key} = time() . "|local|local";
    return "";
  }
  $toboss   = $toaddr;
  $toboss   =~ s/\.\d+$//;
  # Remove my "hpt> " comments
  if ($text =~ /^((?:\x01[^\r]+\r)*)hpt> [^\r]+\r/)
  { $text = "$1$'";
    $change = 1;
  }
  compileNL() unless $nltied;
  if ($nltied && !defined($nodelist{$toboss}))
  {
    bounce($fromname, $fromaddr, $toname, $toaddr, $date, $subject, $text,
           "Node $toboss mising in $curnodelist");
    return "Node $toboss mising in $curnodelist";
  }
  if ($fromaddr eq $myaddr[0] &&
      !isattr("cpt", $attr) &&
      $area =~ /^netmail$/i &&
      $fromname !~ /areafix|crazy mail robot|allfix|ping|uucp/i)
  { putMsgInArea("I_SENT", $fromname, $toname, $fromaddr, $toaddr,
              $subject, $date, "pvt sent read", $text, 0);
  }
  if ($toaddr eq $myaddr[0])
  { if ($toname =~ /^faqserver$/i)
    {
      faqserv($fromaddr, $fromname, $subject, $text);
      $newnet = 1;
      return "Message to FaqServer";
    }
    unless ($toname =~ /^(areafix|allfix|filefix)$/i)
    { putMsgInArea("GUL", $fromname, $toname, $fromaddr, $toaddr,
                $subject, $date, "pvt sent read", $text, 0);
      return "Message to gul";
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

  return _route($toaddr, $attr, $text);
}

sub _route
{
  my ($toaddr, $attr, $text) = @_;

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
  my (@route, $dest, $patt, $boss, $host, $flags);

  compileNL() unless $nltied;

  if (isattr("att", $attr))
  { @route = @routefile;
  } else
  { @route = @routemail;
  }
  $addr =~ s/\.0$//;

  $flags = $1 if $text =~ /^(.*\r\n?)?\x01FLAGS\s+(\S[^\r]*\S)\s*\r/;
  $flags =~ tr/A-Z/a-z/;
  foreach $flavour ("hld", "dir", "crash", "imm")
  { if (str2attr($flavour) != -1)
    { if ($attr & str2attr($flavour))
      {
        $flavour = "hold" if $flavour eq "hld";
        return $addr;
      }
    } else
    {
      if (index($flags, $flavour) >= 0)
      {
        $flavour = "immediate" if $flavour = "imm";
        return $addr;
      }
    }
  }

  foreach (@route)
  { ($flavour, $dest, $patt) = split(/\s+/, $_);
    $boss = $addr;
    $boss =~ s/\..*//;
    $host = $boss;
    $host =~ s#/.*#/0#;
    if ($patt =~ /^hub(.*)/i)
    { $_ = $1;
      if ($nodelist{$boss} =~ /,(.*)/)
      { $patt = ".*" if $_ eq $1;
      }
    } elsif ($patt =~ /^reg(.*)/i)
    { $_ = $1;
      if ($nodelist{$host} =~ /^(.*),/)
      { $patt = ".*" if $_ eq $1;
      }
    }
    if ($addr =~ /^$patt$/)
    { if ($dest eq "noroute")
      { $dest = $addr;
      } elsif ($dest eq "boss")
      { $dest = $boss;
      } elsif ($dest eq "host")
      { $dest = $host;
      } elsif ($dest eq "hub")
      { $dest = $boss;
        if ($nodelist{$boss} =~ /,(.*)/)
        { $dest = $1;
        } else
        { $dest = $host;
        }
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
  if (@areas)
  { putlist();
    @areas = ();
  }
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
  my($crc, $a, $mtime, $size, $pktstart);
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
  ($size,$mtime) = (stat($pktname))[7,9];
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
  opendir(F, nodelistDir()) || return;
  @nlfiles = grep(/^nodelist\.\d\d\d$/i, readdir(F));
  closedir(F);
  return unless @nlfiles;
  $curnodelist = pop(@nlfiles);
  ($curmtime,$curctime) = (stat(nodelistDir . "/$curnodelist"))[9,10];
  foreach(@nlfiles)
  { ($mtime,$ctime) = (stat(nodelistDir . "/$_"))[9,10];
    if ($mtime > $curmtime)
    { $curmtime = $mtime;
      $curctime = $ctime;
      $curnodelist = $_;
    }
  }
  ($mtime,$ctime) = (stat($nldb))[9,10];
  if (!defined($mtime) || $mtime < $curmtime)
  {
    unlink(nldb);
    tie(%nodelist, 'DB_File', nldb, O_RDWR|O_CREAT, 0644) || return;
    unless (open(F, "<".nodelistDir()."/$curnodelist"))
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
  putMsgInArea("", "Crazy Mail Robot", $fromname, "", $toaddr,
            "Unable to delivery", "", "pvt k/s loc cpt", $bouncetext, 1);
  $newnet = 1;
  return $reason;
}

sub isattr
{
  my($sattr, $attr) = @_;
  return $attr & str2attr($sattr);
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
    $fsize = (stat(faq . "$_.faq"))[7];
    if (($size += $fsize) > 102400)
    { $reply .= "Size limit riched, rest skipped\r";
      $skip = 1;
      next;
    }
    if (open(F, "<" . faq . "$_.faq"))
    { read(F, $topic, $fsize);
      putMsgInArea("", "FaqServer", $fromname, "", $fromaddr,
                "Topic $_", "", "pvt loc k/s cpt", "Topic $_", $topic, 1);
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
      putMsgInArea("", "FaqServer", $fromname, "", $fromaddr,
                "Help response", "", "pvt loc k/s cpt", $topic, 1);
      close(F);
    }
  }
  putMsgInArea("", "FaqServer", $fromname, "", $fromaddr,
            "FaqServer reply", "", "pvt loc k/s cpt", $reply, 1);
}

sub putlist
{
  my(%areas, $fromaddr, $areaname, $desc);
  local(*F);

  %areas = ();
  $fromaddr = shift(@areas);
  while(@areas)
  {
    $_ = shift(@areas);
    next unless /^(\S+)(?:\s+(\S.*)|\s*)$/;
    ($areaname, $desc) = ($1, $2);
    $desc = "" if $desc =~ /autocreated|new\/unsorted|description missing/i;
    $desc = "" if $desc =~ /^(Regional|Gated) [Ee]choe?s$/;
    if (defined($areas{$areaname}))
    { next if $desc eq "";
      $areas{$areaname} = $desc;
    }
    else
    { $areas{$areaname} = $desc;
    }
  }
  return if listname($fromaddr) eq "";
  open(F, ">".listdir().listname($fromaddr)) || return;
  foreach (sort keys %areas)
  { print F "$_ " . $areas{$_} . "\n";
  }
  close(F);
  return;
}

sub arqcpt
{
  my($fromaddr, $toaddr, $fromname, $toname, $subject, $date, $attr, $origtext) = @_;
  my($text, $route);
  $route = _route($toaddr, $attr, $origtext);
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
  putMsgInArea("", "Crazy Mail Robot", $fromname, "", $fromaddr,
            "Audit Receipt Response", "", "pvt k/s loc cpt", $text, 1);
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
  putMsgInArea("", "Crazy Mail Robot", $fromname, "", $fromaddr,
            "Return Receipt Response", "", "pvt k/s loc cpt", $text, 1);
  $newnet = 1;
}
