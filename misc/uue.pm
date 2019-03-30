#!/usr/bin/perl
#
# Auto uuedecode from messages for HPT perl (c) Stas Mishchenkov 2:460/58
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
# Usage:
# Put uue.pm somewere in @INC path. It's strongly recomended
# to put it in the same directory with filter.pl.
# Insert into HPT config file somthing like:
# hptperlfile /home/fido/perl/filter.pl
# and place to filter.pl some like this:
# use uue;
# sub put_msg {
#     return uu_decode( $area, $text );
# }
# or
# sub put_msg 
# {
#     if ( uu_decode( $area, $text ) == 0 ) {
#         $text =~ s/\rbegin 644[ ]+([^ \r]+)\r[^ ]*\rend\r/\rbegin 644 $1\r\[ uue skipped \]\rend\r/g;
#         $change=1;
#     }
#     return 1;
# }
#
# uu_decode( $area, $text ) returns 0 if uue detected and 1 otherwise.
#
#

sub uu_decode($$)
{
	local ($marea, $mtext) = @_;

	local $uudecoded_data;
	$config{protInbound} =~ /([\\\/])/;
	local $slash = $1;
	local $uuedir = $config{protInbound}."uue";
	mkdir $uuedir if !-e $uuedir;
        # директория, в которой складывать разююки.
	if ( $mtext =~ /\rbegin 644[ ]+([^ \r]+)\r([^ ]*\r)end\r/i ){
	    my @uuelines = split(/\r/,$2);
	    my $decdir = $uuedir . $slash . uc($marea);
	    my $ofile = $decdir . $slash . $1;
	    mkdir $decdir if !-e $decdir;
	    my $i = 0;
	    while (-e $ofile) {
		$ofile = $decdir . $slash . sprintf("%08x", time()) . 
			 sprintf("%02x",$i)."$1";
		$i++;
		if ($i > 255) {
		    $ofile = $decdir . $slash . $1;
		    unlink($ofile);
		}
	    }
	    if (open(F, ">>$ofile")){
		binmode(F);
		foreach my $val ( @uuelines ){
		    $uudecoded_data = unpack("u", "$val");
		    print(F $uudecoded_data);
		}
		close(F);
		undef @uuelines;
		return 0;
	    } else {
		w_log("Can't open \"$ofile\"\: $!\.");
	    }
	}
return 1;
}

1;
