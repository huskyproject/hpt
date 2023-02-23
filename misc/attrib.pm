#!/usr/bin/perl
#
=head1  NAME

    attrib.pm - two subs to handle ARQ and RRQ message attributes for HPT perl
    by Stas Mishchenkov 2:460/58.

=head1 SYNOPSIS

   use attrib;
   
   sub filter()
   {
      is_rrq( $attr );
   }
   
   sub route()
   {
      is_arq( $attr, $route );
   }
   
   $attr - message attributes as defined by HPT perl.
   $route - message routing as defined by HPT perl.

=head1 DESCRIPTION

   This subs to handle ARQ and RRQ message attributes for HPT perl designed
   according to FTS-0001.016.
   Insert into HPT configuration file:
      hptperlfile /home/fido/perl/filter.pl

   Put attrib.pm somewhere in the @INC path. It's strongly recommended for Windows
   users to put it in the same directory with filter.pl.
   place to filter.pl something like this:

   use attrib;
   
   sub filter()
   {
      is_rrq( $attr );
   }
   
   sub route()
   {
      is_arq( $attr, $route );
   }
   
   $attr - message attributes as defined by HPT perl.
   $route - message routing as defined by HPT perl.

=head1 RETURN VALUE

   Both subs return 1 if ARQ or RRQ attribute found, 0 - otherwise.

=head1 AUTHOR

   Stas Mishchenkov 2:460/58.

=head1 COPYRIGHT AND LICENSE

   This library is free software; you may redistribute it and/or
   modify it under the same terms as Perl itself.
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

=head1 SEE ALSO
   B<FTS-0001.016> http://ftsc.org/docs/fts-0001.016

=cut

sub is_arq($;$)
{
    my ( $attrr, $rou ) = @_;
    $attrr = attr2str( $attrr );
    my $m_txt = $text;
    my $reply = '';
    if ( $m_txt =~ /\x01MSGID: ([^\r]+)\r/ ) {
	$reply = "\x01REPLY: $1\r";
    }
    $m_txt =~ s/\r[^\x01\r]*/\r/g;
    $m_txt =~ s/[\r]{2,}/\r-----------------------\r\[Message body skipped\]\r-----------------------\r/;
    $m_txt =~ s/\x01/\@/g;
    if ( defined( $rou ) ) {
	$rou = "and routed via $rou";
    } else {
	$rou = ''; 
    }
    
    if ( $attrr =~ /\bArq\b/i ) {
	w_log( "ARQ. Flags \'$attrr\' detected." );
	putMsgInArea( '', $config{sysop}, $fromname,
                   @{$config{addr}}[0], $fromaddr, 'Audit receipt.',
                   undef, $LOC+$PVT+$RRC, "${reply}Hello $fromname.\r\r".
                            "Your message has successfully reached my system $rou.\r\r".
                            "----------------------------------------------------------\r".
                            " From: ". sprintf( "%-36s    $fromaddr\r", $fromname ).
                            " To  : ". sprintf( "%-36s    $toaddr\r", $toname ).
                            " Subj: ". sprintf( "%-71s\r", $subject ).
                            "----------------------------------------------------------\r".
                            $m_txt .
                            "----------------------------------------------------------\r".
                            "\r--- \r" );
        return 1;
    }
    return 0;
}

sub is_rrq($)
{
    my ( $attrr ) = @_;
    $attrr = attr2str( $attrr );
    my $m_txt = $text;
    my $reply = '';
    if ( $m_txt =~ /\x01MSGID: ([^\r]+)\r/ ) {
	$reply = "\x01REPLY: $1\r";
    }
    $m_txt =~ s/\r[^\x01\r]*/\r/g;
    $m_txt =~ s/[\r]{2,}/\r-----------------------\r\[Message body skipped\]\r-----------------------\r/;
    $m_txt =~ s/\x01/\@/g;
    
    if ( $attrr =~ /\bRrq\b/i ) {
	w_log( "RRQ. Flags \'$attrr\' detected." );
	putMsgInArea( '', $config{sysop}, $fromname,
                   @{$config{addr}}[0], $fromaddr, 'Return of receipt.',
                   undef, $LOC+$PVT+$RRC, "${reply}Hello $fromname.\r\r".
                            "Your message has successfully reached my system.\r\r".
                            "----------------------------------------------------------\r".
                            " From: ". sprintf( "%-36s    $fromaddr\r", $fromname ).
                            " To  : ". sprintf( "%-36s    $toaddr\r", $toname ).
                            " Subj: ". sprintf( "%-71s\r", $subject ).
                            "----------------------------------------------------------\r".
                            $m_txt .
                            "----------------------------------------------------------\r".
                            "\r--- \r" );
        return 1;
    }
    return 0;
}

1;
