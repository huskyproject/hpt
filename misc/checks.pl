#/usr/bin/perl

my @Id = split(/ /,'$Id checks.pl,v 1.q 2010/01/22 11:49:30 stas_degteff Exp $');

# Several checks for messages (perl hook for HPT)
# (c) 2010 Grumbler
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

# The checksfilter() subroutine should 
#
# usage example:
# ==============
# BEGIN{ require "checks.pl" }
# sub filter() {
#   my $r=checksfilter();
#   return $r if( length($r)>0 );
#   ...some other functions...
# }
# sub process_pkt{}
# sub after_unpack{}
# sub before_pack{}
# sub pkt_done{}
# sub scan{}
# sub route{}
# sub hpt_exit{}
# ==============

## Settings:
#
@fromrobotnames = (   # Names if remote robots, don't pass these messages to local robots
                "MAILER-DAEMON",
                "areafix",
                "filefix",
                "devnull"
              );
@myrobotnames = (     # Names of local robots
                "areafix",
                "filefix",
                "mirror robot",
                "ping-pong robot",
                "Messages check robot"
               );

my $maxmailsize=10485760; # 1 Mb # max message is allowed
my $check_msgsize=1;         # Check and stop big messages
my $check_CHRS=1;            # Check violates FTS - CHRS kludge
my $check_CHRS_IMBPC=0;      # Check violates FTS - "^ACHRS: IBMPC 2" is obsoleted
my $check_CHRS_FIDO7=1;      # Check violates FTS - "^ACHRS: FIDO7 2", "^ACHRS: +7_FIDO 2"
my $bounce_nondelivery=0;           # Bounce about non-delivery mail
my $bounce_violates=0;              # Bounce about FTS violates

my $reportArea="ERRORS";

my $myname="Messages check robot";  # Robot name, uses in report
my $bounce_subj="$myname bounce";   # Subject of bounce message

my $sysopname="Sysop";              # Report destination name
my $sysopaddr=$myaddr.".1";         # Report destination address
my $report_subj="$myname report";           # Subject of report message
my $report_origin="$myname: HPT-perl hook"; # Origin of report message

################################################################################
my $report_tearline="$Id[1] $Id[2]";
(my $file=$Id[1]) =~ s/,v$//;
undef @Id;
$myaddr=(myaddr())[0] if( !scalar($myaddr) or ($myaddr eq "") );

$check_msgsize=0 if($maxmailsize<=0);

sub checksfilter{
  my $msgid=undef;
  if( $text =~ /^(.*\r)?\x01MSGID: ([^\r]+)\r/m ){
    $msgid = "$2";
  }
  my $pid_eid=undef;
  if( $text =~ /^(.*\r)?\x01[PE]ID: ([^\r]+)\r/m ){
    $pid_eid = "$2";
  }
  my $tearline=undef;
  if( $text =~ /^(.*\r)?--- ([^\r]+)\r/m ){
    $tearline = "$2";
  }

  if( ! scalar($area) ) # if netmail
  {

    # Checks for robots
    my $fromrobot = grep( /$fromname/i, @fromrobotnames );
    my $torobot = grep( /$toname/i, @myrobotnames );
    return "Message from robot to robot" if( $fromrobot and $torobot );
    undef $fromrobot;

    my $tomyaddr = grep( /$toaddr/i, myaddr() );
    if( $torobot and ! $tomyaddr )
    {
      my $msgtext=$text;
      $msgtext =~ s/\x01/@/gm;
      $msgtext =~ s/\n/\\x0A/gm;
      $msgtext =~ s/\rSEEN-BY/\rSEEN+BY/gm;
      $msgtext =~ s/\r---([ \r])/\r-+-\1/gm;
      $msgtext =~ s/\r \* Origin: /\r + Origin: /gm;
      my $bounce_subj = "Message to not my robot";
      my $bouncetext = "Hello!\r\rYou send message to alien robot via my node. Please send this message directly!.\r"
      . "Original message header:\r From: \"$fromname\" $fromaddr\r To: \"$toname\" $toaddr\r"
      . " Date: $date\r Subj: $subject\r Attr: $attr\r Received from: $pktfrom\r"
      . "Original message text:\r*=========*\r$msgtext\r*=========*\r"
      . "\r--- $report_tearline";
      putMsgInArea("",$myname,$fromname,$myaddr,$fromaddr,$bounce_subj,"","Uns Pvt Loc",$bouncetext,1);
      return $bounce_subj;
    }

    undef $torobot;
  } # if netmail

  # Check for big message
  if ($check_msgsize>0)
  {
    do {use bytes; $len=length($text)};
    if ($len > $maxmailsize)
    { 
      if( $bounce_nondelivery )
      {
        my $bouncetext = "Hello, $fromname!\r\rRegretfully I inform you that your message is rejected because of the excessive size.\r"
              . "Details of rejected message:\r"
              . "From: $fromname, $fromaddr\r"
              . "To: $toname" . (scalar($area)? $toaddr : "") . "\r"
              . "Subject: $subject\r"
              . (scalar($area)? "Area: $area\r" : "")
              . (scalar($msgid)? "MsgID: $msgid\r" : "")
              . (scalar($tid_eid)? "TID: $tid_eid\r" : "")
              . (scalar($tearline)? "Tearline: $tearline\r" : "")
              . "Size: $len bytes\r"
              . "\rSysop of the $myaddr may pass this message manually later or it may conclusively remove this message.\r"
              . "\r--- $report_tearline\r * Origin: $report_origin ($myaddr)\r";
        putMsgInArea("",$myname,$fromname,$myaddr,$fromaddr,$bounce_subj,"","Uns Pvt Loc",$bouncetext,1);
      }
      w_log('C', "Perl($file): Message from $fromaddr "
               .(scalar($area)? "in $area":"to $toaddr")
               . " too large, drop into badarea"
               . ( $bounce_nondelivery? ", bounce created." : "." ) );
      return "Message too large - must be approved manually"; # drop into badarea
    }
  }

  # check for CHRS kludge
  if( $check_CHRS>0 )
  {
    my @chrs = grep /^\x01CHRS:/, split(/\r/,$text);
    if( $#chrs > -1 )
    {
      my $msgtext="";
      if( $#chrs > 0 )
      {
        $msgtext .="* Error: CHRS kludge more one, extra CHRS kludges will ignored\r";
      }
      $chrs[0] =~ s/^\x01/\@/;
      if( $chrs[0] !~ /^\@CHRS:\s+[[:alnum:]-]+\s+[1-4]$/ )
      {
        $msgtext .="* Error: invalid CHRS kludge, should be \"@CHRS: <charset> <level>\" where <level> is number 1..4 and <charset> is (alphanumberic) charset name:\r  " . $chrs[0] . "\r";
      }
      if( $check_CHRS_IMBPC>0 && $chrs[0] =~ /(IBMPC)/ )
      {
        $msgtext .="* Warning: Charset name IBMPC is deprecated: \"" . $chrs[0] . "\"\r";
        if( $fromaddr =~ m(^2:[56][0-9][0-9]{2}?/) )
        {
          $msgtext .="  It's recommended: \@CHRS: CP866 2\r";
          if( ($pid_eid =~ /GED/i) or ($tearline =~ /(GED|Golded)/i) )
          {
            $msgtext ."  To fix, set \"XLATLOCALSET CP866\" in golded.cfg "
                     ."for your Golded on Windows or DOS\r";
          }
        }
      }
      if( $check_CHRS_FIDO7>0 && $chrs[0] =~ /(FIDO|\+7)/ )
      {
        $msgtext .="* Error: Your charset is invalid (and russian fido uses charset CP866 usually):\r"
                ."  Present:     " . $chrs[0] . "\r"
                ."  Recommended: \@CHRS: CP866 2\r"
                 ;
        if( ($pid_eid =~ /GED/i) or ($tearline =~ /(GED|Golded)/i) )
        {
          $msgtext ."  To fix, set \"XLATLOCALSET CP866\" in golded.cfg "
                   ."for your Golded on Windows or DOS\r";
        }
      }
      if( $msgtext )
      {
        if( $bounce_violates ) 
        {
          my $bouncetext = "Hello, $fromname!\r\r"
              . "Regretfully I inform you that your message is violates Fidonet standard.\r"
              . "These message is passed via my node, but I asks for you to fix misconfiguration."
              . "Details of message:\r"
              . "From: $fromname, $fromaddr\r"
              . "To: $toname" . (scalar($area)? $toaddr : "") . "\r"
              . "Subject: $subject\r"
              . (scalar($area)? "Area: $area\r" : "")
              . (scalar($msgid)? "MsgID: $msgid\r" : "")
              . "\r\rInformation about invalid kludge:\r"
              . $msgtext
              . "\r--- $report_tearline\r * Origin: $report_origin ($myaddr)\r";
          putMsgInArea("",$myname,$fromname,$myaddr,$fromaddr,$bounce_subj,"","Uns Pvt Loc",$bouncetext,1);
        }
        $msgtext = "Hello!\r\rMessage with invalid kludge is detected:\r"
              . "From: $fromname, $fromaddr\r"
              . "To: $toname" . (scalar($area)? $toaddr : "") . "\r"
              . "Subject: $subject\r"
              . (scalar($area)? "Area: $area\r" : "")
              . (scalar($msgid)? "MsgID: $msgid\r" : "")
              . ( $bounce_violates? "Bounce to $fromname are created.\r" : "" )
              . "\r\rInformation about invalid kludge:\r"
              . $msgtext
              . "\r--- $report_tearline\r * Origin: $report_origin ($myaddr)\r";
        putMsgInArea($reportArea,$myname,$sysopname,$myaddr,$sysopaddr,$report_subj,"","Uns Loc",$msgtext,1);
      }
    }
  }
}

w_log('U',"$file is loaded");
1;
