#/usr/bin/perl

my @Id = split(/ /,'$Id$');

# Check origin according FTS-4 (perl hook for HPT)
# (c) 2007 Grumbler
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

# Parse Origin line in messages and make several checks. If origin is invalid then sends message to sysop.
#
#
#
#
# usage example:
# ==============
# BEGIN{ require "checkorigin.pl" }
# sub filter() { &checkorigin; }
# sub process_pkt{}
# sub after_unpack{}
# sub before_pack{}
# sub pkt_done{}
# sub scan{}
# sub route{}
# sub hpt_exit{}
# ==============

my $report_tearline="$Id[1] $Id[2]";
(my $file=$Id[1]) =~ s/,v$//;
undef @Id;
$myaddr=(myaddr())[0] if( $myaddr == "" );

sub checkorigin{

 my $sysopname="Sysop";              # Report destination name
 my $sysopaddr="2:5080/102.1";         # Report destination address
 my $myname="Validity check robot";  # Robot name, uses in report
 my $report_subj="$myname report";           # Subject of report message
 my $report_origin="$myname: HPT-perl hook"; # Origin of report message

 my $msgtext="";


 if( $text =~ /\r \* Origin:([^\r]+)/gm ){ # origin line is found
   my $origin=$1;
   if( $origin !~ /^ [^\s]*/ ){ # bad: space after " * Origin:" is required
     $msgtext = "* space after \" * Origin:\" is required, but don\'t presents\r";
   }
   if( $origin =~ /[\s]+$/ ){ # bad: space after " * Origin: text (address)" is prohibited
     $msgtext .= "* space after \" * Origin: text (address)\" is prohibited, but is presents\r";
   }elsif( $origin =~ /[^\)]+$/ ){ # bad: space after " * Origin: text (address)" is prohibited
     $msgtext .= "* any charachters after \" * Origin: text (address)\" is prohibited, but is presents\r";
   }

   if( $origin =~ /(\(| )([0-9]+:)?([0-9]+)\/([0-9]+)(\.[0-9]+)?(\@[a-zA-Z])?\)(\s*)?$/ ){
     my $addrinorigin="$2$3/$4$5";
     if( $1 ne "(" ){ # bad: address and only address should be enclosed into brackets
        $msgtext .= "* text or space in brackets before address is prohibited\r";
     }
     if( $2 =~ /^0+:/ ){ # bad zone number
        $msgtext .= "* bad zone number in address ($2)\r";
     }
     $addrinorigin =~ s/\.0$//;
     if( $fromaddr ne "$addrinorigin" ){
        $msgtext .= "* originating address and address in origin line is different ($fromaddr ~= $addrinorigin\r";
     }
   }
   if( length($msgtext)>0 ){
     $msgtext = "Hello!\r\rFound illegal origin line in area $area from $fromaddr:\r".$msgtext
              . "==== begin of message ====\r"
              . "$text\r"
              . "==== end of message ====\r\r";
     # invalidate control stuff
     $msgtext =~ s/\x01/@/g;
     $msgtext =~ s/\n/\\x0A/g;
     $msgtext =~ s/\rSEEN-BY/\rSEEN+BY/g;
     $msgtext =~ s/\r--- /\r=== /g;
     $msgtext =~ s/\r \* Origin: /\r + Origin: /g;
     # add tearline and origin
     $msgtext .= "--- $report_tearline\r * Origin: $report_origin ($myaddr)\r";
     putMsgInArea("",$myname,$sysopname,$myaddr,$sysopaddr,$report_subj,"","Uns Loc",$msgtext,1);
   }
 }
}

w_log('U',"$file is loaded");
1;
