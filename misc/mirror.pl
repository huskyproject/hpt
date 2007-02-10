#!/usr/bin/perl
# $Id$
# Mirror robot for HPT
# (c) 2006 Gremlin
# (c) 2006 Grumbler
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
# 
sub filter()
{
 my %testarea;
 my $msgtext="";
# ==== настраивать от забора
 my $check_toname="All";
 my $check_subject="test";
 my $myname="Mirror robot";
 my $myaddr="2:5020/545";
 my $txt2pkt="/usr/local/bin/txt2pkt";
 my $report_subj="$myname report";
 my $report_origin="$myname";
 my $pkt_dir="/fido/inbound-local";

 $testarea{"GREMLIN.TEST"}=1;  # echobase is exists
 $testarea{"MU.TEST"}=2;       # passthrough echo
# ==== и до обеда

 my @Id = split(/ /,'$Id$');
 my $report_tearline="$Id[1] $Id[2]";
 undef @Id;

 if( ($testarea{$area}) && ($toname eq $check_toname) && ($toname eq $myname)
     && (lc($subject) eq $check_subject) )
 {
# $text contains original message and must be left as is
  my $msgtext = $text;

# invalidate control stuff
  $msgtext =~ s/\x01/@/g;
  $msgtext =~ s/\n/\\x0A/g;
  $msgtext =~ s/SEEN-BY/SEEN+BY/g;
  $msgtext =~ s/\r--- /\r-+- /g;
  $msgtext =~ s/\r \* Origin: /\r + Origin: /g;
  $msgtext="$date $fromname wrote:\r\r"
	. "==== start message ====\r\r"
	. "$msgtext\r"
	. "==== end of message ====\r\r\r";

  if( $testarea{$area}==1 ){
    $msgtext = $msgtext . "--- $report_tearline\r * Origin: $report_origin ($myaddr)\r";
    putMsgInArea($area,$myname,$fromname,$myaddr,$myaddr,$report_subj,"","Uns Loc",$msgtext,1);

  }else{
    $msgtext =~ s/\r/\n/g;
    my $cmd="$txt2pkt -e $area -xf $myaddr -xt $myaddr -nf '$myname'"
           ." -nt '$fromname' -s '$report_subj' -t '$report_tearline'"
           ." -o '$report_origin' -d '$pkt_dir' -";
    if( open( PIPE,"|$cmd" ) ){
      print PIPE $msgtext;
      close PIPE;
      writeLogEntry('7',"PKT with reply is created from $myname using txt2pkt");
    }else{
      writeLogEntry('1',"Can't open pipe to txt2pkt");
    }
  }
 }
 return "";
}

sub process_pkt{}
sub after_unpack{}
sub before_pack{}
sub pkt_done{}
sub scan{}
sub route{}
sub hpt_exit{}

