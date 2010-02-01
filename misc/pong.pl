#!/usr/bin/perl
#
# Ping-pong robot for HPT. Designed accordingly FTS-5001.002
# (c) 2006 Gremlin
# (c) 2006 Grumbler
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
# Insert into config:
# hptperlfile /home/fido/lib/filter.pl
# and place to filter.pl some like this:
# BEGIN { require "pong.pl"; }
# sub filter{
#   &pong;
# }
#

my $myname='Ping-Pong Robot';
my $Id='$Id$';
my $file=$1 if( $Id =~ /Id: ([^ ]+),v / );
my @myaddr=myaddr();
my $myaddr=$myaddr[0];

sub pong()
{
 my $msgtext="";
 if ((length($area)==0) && ($toname eq "PING") && ($fromname ne "PING"))
 {
   my @Id = split(/ /,$Id);
   my $report_tearline="$Id[1] $Id[2] $Id[3] $Id[4]";
   undef @Id;

   w_log('C',"Perl($file): Make PONG to PING reqiest: area=".((length($area)==0)? "netmail":$area)."; toname=$toname; toaddr=$toaddr fromname=$fromname; fromaddr=$fromaddr" );

# $text contains original message and must be left as is
   $msgtext = $text;
# invalidate control stuff
   $msgtext =~ s/\x01/@/g;
   $msgtext =~ s/\n/\\x0A/g;
   $msgtext =~ s/\r--- /\r-=- /g;
   $msgtext =~ s/\r\ \* Origin: /\r + Origin: /g;

   $msgtext="\rThis is an answer to PING request sent at $date by $fromname:\r\r"
   . "==== begin of request body ====\r\r"
   . "$msgtext\r"
   . "===== end of request body =====\r\r\r"
   . "--- $report_tearline\r"
   ." * Origin: $myname at ($myaddr)\r";
   my $err= putMsgInArea($area,$myname,$fromname,$myaddr,$fromaddr,
                "PONG: ".$subject,"","Uns Loc Pvt K/s cpt",$msgtext,1);
   if( defined($err) ){ w_log('A',"Perl($file): Can't make new message: $err"); }
 }
 return "";
}

w_log('U',"$file is loaded");
1;
