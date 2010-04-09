#!/usr/bin/perl
#
# Receipt robot for HPT: reply on RRQ and ARQ netmail flags
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
# BEGIN { require "receipt.pl"; }
# sub filter{
#   &rrqcpt;
# }
# sub route{
#   &arqcpt;
# }
#

my $flagfile='/fido/flag/netmail-in'; # Flag file for indicating new netmail
my $Id='$Id$';
my $file=$1 if( $Id =~ /Id: ([^ ]+),v / );
my @myaddr=%config? @{$config{addr}} : myaddr();
my $myname="Receipt Robot";
my $report_tearline="$file (HPT perl hook)";

sub arqcpt
{ # This procedure should be called from route() subroutine.

  if ( isattr("arq", $attr) )
  {
w_log('Z', "Perl($file): Netmail with ARQ from $fromaddr to $toaddr");
    my @a = grep(/^$toaddr$/,@myaddr);
    if($#a<0) # not for my
    {
        my $origmsgid=extractmsgid($text);
        my $rcptext = "\x01REPLY: $origmsgid\r" .
          "    Hello $fromname!\r" .
          "\r" .
          "Your message (msgid: $origmsgid) with ARQ passed via $myaddr[0] to $route.\r" .
          "\r" .
          "Original message header:\r" .
          "=============================================================\r" .
          " From:    $fromname, $fromaddr\r" .
          " To:      $toname, $toaddr\r" .
          " Subject: $subject\r" .
          " Date:    $date\r" .
          "=============================================================\r" ;
        my @Via = grep( s/^\x01Via/@Via/, split(/\r/,$text));
        if( $#Via >= 0 )
        {
          $rcptext .= "\rOriginal VIA kludges:\r" . join( "\r", @Via );
        }
        $rcptext .= "\r--- $report_tearline\r";

        my $err = putMsgInArea("", $myname, $fromname, "", $fromaddr,
            "Audit Receipt Response", "", "pvt k/s loc cpt", $rcptext, 1);
        if( defined($err) ){ w_log('A',"Can't make new message: $err"); }
        else
        {
          w_log('C', "Perl($file): ARR created for netmail from $fromaddr to $toaddr message ID $origmsgid");
          open( FLAG, ">>$flagfile" ) && close(FLAG);
        }
    }
  }
  return "";
}

sub rrqcpt
{ # This procedure should be called from filter() subroutine.

  if ( ($area eq "") && isattr("rrq", $attr) )
  {
w_log('Z', "Perl($file): Netmail with RRQ from $fromaddr to $toaddr");
    my @a = grep(/^$toaddr$/,@myaddr);
    if($#a>=0) # for my
    {
        my $origmsgid=extractmsgid($text);
        my $rcptext = "\x01REPLY: $origmsgid\r"
        .  "    Hello $fromname!\r\r"
        .  "Your message to $toname, $toaddr (msgid: $origmsgid) successfully delivered.\r\r"
        .  "Original message header:\r"
        .  "=============================================================\r"
        .  " From:    $fromname, $fromaddr\r"
        .  " To:      $toname, $toaddr\r"
        .  " Subject: $subject\r"
        .  " Date:    $date\r"
        .  "=============================================================\r"
        .  "--- $report_tearline\r";

        my $err = putMsgInArea("", $myname, $fromname, "", $fromaddr,
            "Return Receipt Response", "", "pvt k/s loc cpt", $rcptext, 1);
        if( defined($err) ){ w_log('A',"Can't make new message: $err"); }
        else
        {
          w_log('C', "Perl($file): RRR created for netmail from $fromaddr to $toaddr message ID $origmsgid");
          open( FLAG, ">>$flagfile" ) && close(FLAG);
        }
    }
  }
  return "";
}

sub isattr
{
  my($sattr, $attr) = @_;
  return $attr & str2attr($sattr);
}

sub extractmsgid
{
 my $text = @_[0];
 $text =~ s/\r\n/\r/gs;
 my @lines = split('\r', $text);
 my @msgid = grep(s/^\x01MSGID: //, @lines);
 if( $#msgid >=0 ){
   return $msgid[0];
 }
 return "";
}

w_log('U',"$file is loaded");
1;
