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

# Look messages in specified (echo)aread. Check toname for "All" and robot name
# (now "Mirror robot"), check subject for specified (now "test"), (see
# "Configuration" below). If matchs then post reply with original message text
# and invalidated cludges.
#
# usage example:
# ==============
# BEGIN{ require "mirror.pl" }
# sub filter() { &mirror; }
# sub process_pkt{}
# sub after_unpack{}
# sub before_pack{}
# sub pkt_done{}
# sub scan{}
# sub route{}
# sub hpt_exit{}
# ==============

my @Id = split(/ /,'$Id$');
my $report_tearline = "$Id[1] $Id[2]";
my $file = $Id[1];
$file =~ s/,v$//;
undef @Id;


sub mirror()
{
  my %testarea;
# ==== Configuration # настраивать от забора
  my $check_toname="All";     # Exactly!
  my $check_subject="test";   # Lower case!
  my $myname="Mirror robot";  # Robot name, uses in reply and check "to" name
  my $myaddr="2:5020/545";    # Robot address
  my $txt2pkt="/usr/local/bin/txt2pkt"; # txt2pkt program (with path) uses for post
                                        #  into passthrough areas
  my $report_subj="$myname report";           # Subject of report message
  my $report_origin="$myname: HPT-perl hook"; # Origin of report message
  my $pkt_dir="/fido/inbound-local";          # Directory to write PKT for 
                                              #  passtrough areas
  my @ignore_from_regexp=(               # if these regexp's is matched with $fromname
                         'devnull@f1.ru' #  then message will be ignored.
                         );
 # areas list, value "1" for ordinary areas, value "2" for passthrough areas.
  $testarea{"GREMLIN.TEST"}=1;  # echobase is exists
  $testarea{"MU.TEST"}=2;       # passthrough echo
# ==== End of configuration # и до обеда
  my $msgtext="";

  if( ($testarea{$area}) && (($toname eq $check_toname) || ($toname eq $myname))
      && (lc($subject) eq $check_subject) )
  {
    foreach my $ignore_from (@ignore_from_regexp)
    {
      if( $fromname =~ /$ignore_from/ )
      { return ""; }
    }

# $text contains original message and must be left as is
    my $msgtext = $text;

# invalidate control stuff
    $msgtext =~ s/\x01/@/g;
    $msgtext =~ s/\n/\\x0A/g;
    $msgtext =~ s/\rSEEN-BY/\rSEEN+BY/g;
    $msgtext =~ s/\r--- /\r=== /g;
    $msgtext =~ s/\r \* Origin: /\r + Origin: /g;
    $msgtext="$date $fromname ($fromaddr) wrote:\r\r"
           . "==== begin of message ====\r"
           . "$msgtext\r"
           . "==== end of message ====\r\r\r";

    if( $testarea{$area}==1 ){
      $msgtext = $msgtext
             . "--- $report_tearline\r * Origin: $report_origin ($myaddr)\r";
      putMsgInArea( $area, $myname, $fromname, $myaddr, $myaddr, 
                    $report_subj, "", "Uns Loc", $msgtext, 1 );
    }else{
      $msgtext =~ s/\r/\n/g;
      my $cmd="$txt2pkt -e $area -xf $myaddr -xt $myaddr -nf '$myname'"
             ." -nt '$fromname' -s '$report_subj' -t '$report_tearline'"
             ." -o '$report_origin' -d '$pkt_dir' -";
      if( open( PIPE,"|$cmd" ) ){
        print PIPE $msgtext;
        close PIPE;
        w_log('7',"PKT with reply is created from $myname using txt2pkt");
      }else{
        w_log('1',"Can't open pipe to txt2pkt");
      }
    }
  }
  return "";
}

w_log('U',"$file is loaded");
1;
