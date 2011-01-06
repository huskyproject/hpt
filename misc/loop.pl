#!/usr/bin/perl
# $Id$
# Netmail loop detection robot for HPT
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

# Look netmail messages and compare all "^aVia" lines with local address
# for duplicated path
# If matchs then post (bounce) reply with original message, drop message
# to badmail and report to sysop.
#
# usage example:
# ==============
# BEGIN{ require "loop.pl" }
# sub filter(){ my $r=checkloop(); if( length($r)>0 ){ return $r; } }
# sub process_pkt{}
# sub after_unpack{}
# sub before_pack{}
# sub pkt_done{}
# sub scan{}
# sub route{ if(length(checkloop()>0){ return (myaddr())[0]; } }
# sub hpt_exit{}
# ==============

my $report_area="ERRORS";
my @Id = split(/ /,'$Id$');
my $file = $Id[1];
$file =~ s/,v$//;
my @myaddr=myaddr();
my $myaddr=$myaddr[0];
undef @myaddr;
my $myname="Loop detect robot";               # Robot name, uses in reports
my $report_subj="Loop report";                # Subject of report message
my $report_tearline="$Id[1] $Id[2]: HPT Perl hook"; # Tearline of report message
undef @Id;

sub checkloop()
{

  w_log( 'u',"checkloop(): start (caller: " . caller() );

  if( $area eq "" || $area =~ /netmail/i )
  {
    my $duplines="";
    my @vialines = grep( /^\x01Via /, split("\r",$text) );
#    while( $v=pop(@vialines) )
#    {
#      if( $v =~ m%([0-9]+:[0-9]+/[0-9]+(\.[0-9]+)?(\@[a-zA-z]*)?.*) % ) # Extract FTN address from Via line
#      {
#w_log('z',"checkloop(): check addr " . $1);
#        my @duplicates =  grep( /$1/, @vialines );
#        if( $#duplicates > -1 )
#        { 
#          $duplines .= $v ."\r" . join( "\r", @duplicates ) ."\r";
#w_log('z',"checkloop(): loop lines ");
#        }
#      }
#    }

        for( my $num=$#vialines-1; $num > -1; $num-- )
        {
          if( $vialines[$num] =~ / $myaddr(\@.*)? / )
          {
            if( $vialines[$num+1] !~ /$myaddr(\@.*)? / )
            { # loop detected: message already routed via me
              $duplines += $vialines[$num] . " \r" . $vialines[$num+1];
              last;
            }
          }
          elsif( $route and ($vialines[$num] =~ / $route(\@.* |[^\.]|\.[^0-9])/) )
            # false-positive may be if $vialines[$num] contain point address of $route node
          { # loop detected
              $duplines += $vialines[$num] . "\r" . "and next hop is $route";
              last;
          }            
        }

    if( $duplines ne "" )
    {
      my $msgtext = $text;
        
       # invalidate control stuff
       $msgtext =~ s/\x01/@/gm;
       $msgtext =~ s/\n/\\x0A/gm;
       $msgtext =~ s/\rSEEN-BY/\rSEEN+BY/gm;
       $msgtext =~ s/\r---([ \r])/\r-+-\1/gm;
       $msgtext =~ s/\r \* Origin: /\r + Origin: /gm;
       $duplines =~ s/\x01/@/g;
       $msgtext=
             "\r Loop detected in message from $fromname, $fromaddr to $toname, $toaddr\r"
           . "Loop Via lines" . ($route? " (default destination is $route)" : "") . ":\r"
           . $duplines . "\r"
           . "This message cant' delivered to recipient via my node\r\n"
           . "Original message with all kludges:\r"
           . "==== Message header ====\r"
           . "From:    $fromname, $fromaddr     Date: $date\r"
           . "To:      $toname, $toaddr\r"
           . "Subject: $subject\r"
           . "==== Message text   ====\r"
           . "$msgtext\r"
           . "==== End of message ====\r"
           . "\r--- $report_tearline";

       w_log('7',"Loop detected: Msg from $fromname, $fromaddr to $toname, $toaddr at $date");
       putMsgInArea( $report_area, $myname, $fromname, $myaddr, $myaddr, 
                    $report_subj, "", "Uns Loc" . ($report_area? "":"pvt"), $msgtext, 1 );
       putMsgInArea( "", $myname, $fromname, $myaddr, $fromaddr, 
                    $report_subj, "", "Uns Loc pvt cpt", $msgtext, 1 );
       return "Loop detected";
    }
  }
  return "";
}

w_log('U',"$file is loaded");
1;
