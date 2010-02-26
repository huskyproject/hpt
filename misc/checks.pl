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

@fromrobotnames = (
                "MAILER-DAEMON",
                "areafix",
                "filefix",
                "devnull"
              );
@myrobotnames = (
                "areafix",
                "filefix",
                "mirror robot",
                "ping-pong robot",
                "Messages check robot"
               );


my $maxnetmailsize=10485760; # 1 Mb max netmails is allowed
my $myname="Messages check robot";  # Robot name, uses in report
my $bounce=1;
my $bounce_subj="$myname bounce";   # Subject of bounce message

my $reportArea="ERRORS";

my $report_tearline="$Id[1] $Id[2]";
(my $file=$Id[1]) =~ s/,v$//;
undef @Id;
$myaddr=(myaddr())[0] if( $myaddr == "" );

my $sysopname="Sysop";              # Report destination name
my $sysopaddr=$myaddr.".1";         # Report destination address
my $report_subj="$myname report";           # Subject of report message
my $report_origin="$myname: HPT-perl hook"; # Origin of report message

sub checksfilter{

 my $msgtext="";

 if( ! scalar($area) ) # netmail
 {

   # Checks for robots
   $fromrobot = grep( /$fromname/, @fromrobotnames );
   $torobot = grep( /$toname/, @myrobotnames );
   return "Message from robot to robot" if( $fromrobot and $torobot );
   undef $torobot;
   undef $fromrobot;

   # Check for big netmail
   do {use bytes; $len=length($text)};
   if ($len > $maxnetmailsize)
   { my $msgid=undef;
     if( $text =~ /^\x01MSGID: (.+)\r/ ){
       $msgid = "with MSGID \"$1\"";
     }
     if( $bounce ) {
       $msgtext = "Hello, $fromname!\r\rRegretfully I inform you that your message is rejected because of the excessive size.\r"
              . "Details of rejected message:\r"
              . "From: $fromname, $fromaddr\r"
              . "To: $toname" . (scalar($area)? $toaddr : "") . "\r"
              . "Subject: $subject\r"
              . (scalar($area)? "MSGID: $msgid\r" : "")
              . "\rSysop of the $myaddr may pass this message manually later or it may conclusively remove this message.\r"
              . "\r--- $report_tearline\r * Origin: $report_origin ($myaddr)\r";
       putMsgInArea("",$myname,$fromname,$myaddr,$fromaddr,$report_subj,"","Uns Pvt Loc",$msgtext,1);
     }
     w_log('C', "Perl($file): Message from $fromaddr "
               .(scalar($area)? "in $area":"to $toaddr")
               . " too large, drop into badarea"
               . ( $bounce? ", bounce created." : "." ) );
     return "Message too large - must be approved manually"; # drop into badarea
   }
 }

}

w_log('U',"$file is loaded");
1;
