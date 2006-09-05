#!/usr/bin/perl
# $Id$
# Mirror robot for HPT
# (c) 2006 Gremlin
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
 $testarea{"GREMLIN.TEST"}=1;
 $testarea{"R50.DIAGNOSTICS"}=1;
# ==== и до обеда

 if( ($testarea{$area}) && ($toname eq $check_toname)
     && (lc($subject) eq $check_subject) )
 {
# $text contains original message and must be left as is
  $msgtext = $text;

# invalidate control stuff
  $msgtext =~ s/\x01/^A /g;
  $msgtext =~ s/SEEN-BY/SEEN+BY/g;
  $msgtext =~ s/\n--- /\n-+- /g;
  $msgtext =~ s/\n \* Origin: /\n + Origin: /g;
  $msgtext="$date $fromname wrote:\r\r"
	. "==== start message ====\r\r"
	. "$msgtext\r"
	. "==== end of message ====\r\r\r"
	. "--- mirror.pl\r"
	." * Origin: $myname ($myaddr)\r";

   putMsgInArea($area,$myname,$fromname,$myaddr,$myaddr,$myname . " report","","Uns Loc",$msgtext,1);
 }
 return "";
}
