#!/usr/bin/perl
#
=head1  NAME

    pingpong.pm - Ping robot for HPT perl. (c) Stas Mishchenkov 2:460/58.

=head1 SYNOPSIS

   use pingpong;

   sub filter{
      ping_pong( $fromname, $fromaddr, $toname, $toaddr, $subject, $text );
   }


   $fromname - sender name
   $fromaddr - sender address
   $toname - recipient's name
   $toaddr - recipient address for netmail or undef
   $area - area for echomail, otherwise undef
   $secure - current message received via SecureInbound
   $subject  - subject of message
   $text - text message (with kludges)


=head1 DESCRIPTION

   This program is Ping robot designed accordingly FTS-5001.006
   This is an extended implementation that allows the Ping response to be
   redirected through any password protcted link.

Insert into HPT configuration file:

    hptperlfile /home/fido/perl/filter.pl

Put pingpong.pm somewere in @INC path. It's strongly recomended for Windows
users to put it in the same directory with filter.pl.

place to filter.pl some like this:

  use pingpong;

  sub filter{
   if ( !defined( $area ) ) {
     ping_pong( $fromname, $fromaddr, $toname, $toaddr, $subject, $text );
   }
  }

   $fromname - sender name
   $fromaddr - sender address
   $toname - recipient's name
   $toaddr - recipient address for netmail or undef
   $area - area for echomail, otherwise undef
   $secure - current message received via SecureInbound
   $subject  - subject of message
   $text - text message (with kludges)


To use "%RouteTo:" command you should place in filter.pl

   sub route{
     return route_to();
   }

=head1 RETURN VALUE

Nothing.

=head1 AUTHOR

   Stas Mishchenkov 2:460/58.

=head1 COPYRIGHT AND LICENSE

   This library is free software; you may redistribute it and/or
   modify it under the same terms as Perl itself.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

=head1 SEE ALSO

B<FTS-5001.006> http://ftsc.org/docs/fts-5001.006

=cut


sub ping_pong($$$$$$)
{
    my ( $from_name, $from_addr, $to_name, $to_addr, $subj, $mtext ) = @_;
    my $addline = "";
    my $msgdirection = "passed through";
    my $time = localtime;

    if ($to_name =~ /^Ping$/i){
	w_log("Ping message detected." );
	$mtext =~ s/\r\x01/\r\@/g;
        $mtext =~ s/^\x01/\@/;
        $mtext =~ s/\r--- /\r-+- /g;
        $mtext =~ s/\r \* Origin\:/\r \+ Origin\:/g;
        $mtext =~ s/\r\%RouteTo\:/\r\@RouteTo\:/gi;
	if ( istous($to_addr) == 1 ) {
		if ( $subj =~ /\%RouteTo\: (\d\:\d+\/\d+)/i) {
		    $addline = "\r\%RouteTo\: $1\r";
		}
		if ( $subj =~ /\%Links/i) {
		    $addline = "My links are:\r~~~~~~~~~~~~~\r";
		    foreach my $key( sort keys %links) {
		    $addline = $addline . sprintf("%-20s", $key) .
		    "$links{$key}{name}\r" if defined $links{$key}{password} &&
				     $key =~ /^\d+\:\d+\/\d+$/ &&
				     $links{$key}{name} !~ /Our virtual lin/i;
		    }
		}
		$msgdirection = "was received by";
	}
	putMsgInArea("NetMail", "Ping Robot", $from_name, "", $from_addr,
		"Pong", "", $UNS, "Hi $from_name.\r\r".
		"   Your ping-message $msgdirection my system at $time\r\r".
		"$addline".
		"---------- Help ------------------------------------------------------------\r".
		"  Also You may use following commands in Subject line:\r".
		"  \%RouteTo\: \<3D_address\> \- The ping robot reply will be routed via\r".
		"                           this node. It MUST be my password protcted link.\r".
		"  \%Links                 \- Get the list of my password protcted links.\r".
		"  -------- Example ---------------------------------------------\r".
		"  From: ".sprintf("%-32s", $from_name)."$from_addr\r".
		"  To  : Ping                            @{$config{addr}}[0]\r".
		"  Subj: %RouteTo: 2:292/854\r".
		"  --------------------------------------------------------------\r".
		"   - The answer to this message will be routed via 2:292/854.\r".
		"----------------------------------------------------------------------------\r".
		"\rOrignal message:\r".
		"============================================================================\r".
		"From: ".sprintf("%-32s",$from_name).sprintf("%-20s",$from_addr)."$date\r".
		"To  : ".sprintf("%-32s",$to_name)."$to_addr\r".
		"Subj: $subj\r".
		"============================================================================\r".
		"$mtext".
		"============================================================================\r".
		"--- perl on $hpt_version\r * Origin: $config{origin} \(@{$config{addr}}[0]\)", 1);
    }
}


sub istous($)
{
    my ( $addrr ) = @_;
    for my $cfg_addr ( @{$config{addr}} ) {
	if( $addrr eq $cfg_addr ) {
	    return 1;
	}
    }
return 0;
}


sub route_to()
{
    if ( $text =~ /\r\%RouteDir\:\s+(\d+\:\d+\/\d+\.?\d*)\s*(\d+\:\d+\/\d+){0,1}/i){
        return '' if defined( $2 ) && istous( $2 ) == 0;
        $route = $1;
	$route =~ /\d+\:\d+\/\d+(\.?\d*)/;
	$route .= '.0' unless defined( $1 );
        $flavour = 'direct';
	w_log("\%RouteDir to $route");
        $text =~ s/\r\%RouteDir\:\s+(\d+\:\d+\/\d+\.?\d*)\s*(\d+\:\d+\/\d+){0,1}/\r\x01Routed_Direct\: $1 at @{$config{addr}}[0]/i;
        $change=1;
    }
    if ( $text =~ /\r\%RouteHold\:\s+(\d+\:\d+\/\d+\.?\d*)\s*(\d+\:\d+\/\d+){0,1}/i){
        return '' if defined( $2 ) && istous( $2 ) == 0;
        $route = $1;
	$route =~ /\d+\:\d+\/\d+(\.?\d*)/;
	$route .= '.0' unless defined( $1 );
        $flavour = 'hold';
	w_log("\%RouteHold to $route");
        $text =~ s/\r\%RouteHold\:\s+(\d+\:\d+\/\d+\.?\d*)\s*(\d+\:\d+\/\d+){0,1}/\r\x01Routed_Hold\: $1 at @{$config{addr}}[0]/i;
        $change=1;
    }
    
    if ( $text =~ /\r\%RouteTo\:\s+(\d+\:\d+\/\d+\.?\d*)\s*(\d+\:\d+\/\d+){0,1}/i){
	return '' if defined( $2 ) && istous( $2 ) == 0;

	if ( defined( $links{$1}{password} ) ) {
	    w_log("\%Route to $1");
	    $route = $1;
	    $route =~ /\d+\:\d+\/\d+(\.?\d*)/;
	    $route .= '.0' unless defined( $1 );
	    $text =~ s/\r\%RouteTo\:\s+(\d+\:\d+\/\d+\.?\d*)\s*(\d+\:\d+\/\d+){0,1}/\r\x01RoutedTo\: $1 at @{$config{addr}}[0]/i;
	    $change=1;
	} else {
	    $addline = "\rMy links are:\r~~~~~~~~~~~~~\r\r";
	    foreach $key( sort keys %links) {
	    $addline = $addline . sprintf("%-20s", $key) .
	    "$links{$key}{name}\r" if defined $links{$key}{password} &&
			     $key =~ /^\d+\:\d+\/\d+$/ &&
			     $links{$key}{name} !~ /Our virtual lin/i;
	    }
	    putMsgInArea("NetMail", "Evil Robot", $fromname, "", $fromaddr,
	    "Routing", "", $UNS, "Hi $fromname.\r\r".
	    "   You you use command \"\%RouteTo:\" and wish to change ".
	    "the routing of your message from default via \"$route\" to \"$1\"".
	    ", but it is not my passworded link. Your message routed by ".
	    "default.\r\r$addline\r\r".
	    "--- perl on $hpt_version\r * Origin: $config{origin} \(@{$config{addr}}[0]\)", 1);
	    $newmail = 1;
	}
    }
return $route;
}

1;
