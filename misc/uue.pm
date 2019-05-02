#!/usr/bin/perl
#
# UUE library for HPT perl (c) Stas Mishchenkov 2:460/58
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
# for Windows users to put it in the same directory with filter.pl.
#
# Insert into config:
# hptperlfile /home/fido/lib/filter.pl
# and place to filter.pl some like this:
#
# use uue;
#
# sub put_msg {
#     return uu_decode( $area, $text );
# } 
# if uue detected and decoded the message will not be placed in the area.
#
# or
# sub put_msg()
# {
#     if ( uu_decode( $area, $text ) == 0 ) {
#         $text =~ s/\rbegin 644[ ]+([^ \r]+)\r[^ ]*\rend\r/\rbegin 644 $1\r\[ uue skipped \]\rend\r/g;
#         $change=1;
#     }
#     return 1;
# }
# if uue detected and decoded uue code will be deleted from the message and
# the message will be placed in the area.
#
# or
# sub filter()
# {
#     uu_decode( $area, $text,undef,1 ) if defined( $area );
# }
# uue will be decoded from all echo areas. Decoded files will owerwrite
# existing files and palced in UUE directory in ProtInbound from HPT config
# file.
#
# or
# sub filter()
# {
#     uu_decode( 'NetMail', $text, '/home/fido/files' ) if !defined( $area );
# }
# uue will be decoded from netmail area. Decoded files will owerwrite
# existing files and palced in '/home/fido/files/NETMAIL' directory.
#
# uu_decode( $area, $text, $decodedir, $owerwrite );
#            $area - Areatag. MUST be the echo area tag or 'NetMail'
#            $text - MUST be message text
#            $decodedir - Should be the full path to the directory, where you
#                         wish to decode files. If not present, Default name is
#                         UUE in ProtInbound from HPT config file.
#            $owerwrite - Should be 1, if you wish to owerwrite existing files
#                         by decoded files, 0 or undefined, - if no.
#                         Default is do not owerwrite existing files by
#                         renaming decoded files.
# returns 0 if uue detected and 1 otherwise.
#
# uu_encode($filename, $mode);
#           $filename - Fully qualified filename (with path) of file you wish
#                       to uu encode.
#           $mode     - May be omitted. Default is 644.
#
#
# Also it can be used in any perl script without HPT.
# Like this:
#---- decode.pl ----
# !/usr/bin/perl
# use uue;
#
# my ($uuefile, $text, $size);
#
# if ( defined( @ARGV[0] ) ) {
#     $uuefile = @ARGV[0];
# } else { die "Usage: dec.pl path/filename.ext\n\n"; }
#
# my $size = -s $uuefile;
# print "Decoding $uuefile, $size bytes\n";
#
# if ( open(F, "<$uuefile") ) {
#    binmode(F);
#    read(F, $text, $size);
#    close(F);
#    uu_decode("decoded", $text, '/home/fido/files', 1);
# }
#---- decode.pl ----
#
# or like this:
#---- encode.pl ----
# !/usr/bin/perl
# use uue;
#
# my ($binfile, $uuefile);
#
# if ( defined( @ARGV[0] ) ) {
#    $binfile = @ARGV[0];
#    $uuefile = @ARGV[0] .".uue";
# } else { die "Usage: dec.pl path/filename.ext\n\n"; }
# 
# if ( open(F, ">$uuefile") ) {
#    binmode(F);
#    print( F uu_encode( $binfile ) );
#    close(F);
# }
#---- encode.pl ----
# 


sub uu_decode($$;$$)
{
	local ($marea, $mtext, $uuedir, $overwrite) = @_;
	local ($slash, $uudecoded_data, @uuelines, $decdir, $ofile);

	if ( $config{protInbound} =~ /([\\\/])/ ){
		$slash = $1;
	} else {
		$ENV{TMP} =~ /([\\\/])/;
		$slash = $1;
	}
	if ( !defined($uuedir) ){
		$uuedir = $config{protInbound}."uue";
	} else {
		if ($uuedir =~ /(.*)[\\\/]$/){
			$uuedir = $1;
		}
	}
	local ($i, $d) = (0, $uuedir);
	while ( -e $uuedir && !-d $uuedir) {
		$uuedir = sprintf( "$d\.%04x", $i);
		$i++;
		if ($i >= 65535) { # maximum files for FA32 file system.
			w_log("So may files \"$uuedir\".") if defined($config{protInbound});
			print STDERR "So may files \"$uuedir\".\n";
			return 1;
		}
	}
	mkdir $uuedir if !-e $uuedir;
	$i = 1;
	while ( $mtext =~ /\r\n?begin 644[ ]+([^ \r\n?]+)\r\n?([^ ]*?\r\n?)end\r\n?/i ){
	    @uuelines = split(/\r\n?/,$2);
	    $decdir = $uuedir . $slash . uc($marea);
	    $ofile = $decdir . $slash . $1;
	    $ofile = find_free_filename($ofile) if !$overwrite;
	    mkdir $decdir if !-e $decdir;
	    if (open(F, ">$ofile")){
		binmode(F);
		foreach my $val ( @uuelines ){
		    $uudecoded_data = unpack("u", $val);
		    print(F $uudecoded_data);
		}
		close(F);
		undef @uuelines;
		$i = 0;
	    } else {
		w_log("Can't open \"$ofile\"\: $!\.") if defined($config{protInbound});
		print STDERR "Can't open \"$ofile\"\: $!\.\n";
	    }
	$mtext =~ s/\r\n?begin 644[ ]+[^ \r\n?]+\r\n?[^ ]*?\r\n?end\r\n?/\r\n/i;
	}
return $i;
}


sub uu_encode($;$)
{

    local ($filename, $mode) = @_;
    local ($uuestr, $bindata);

    $mode ||= "644";
    if ( $filename =~ /([^\\\/]+)$/ ) {
       $uuestr = "\rbegin $mode $1\r";
    } else {
        w_log("Full path MUST be specified. $filename has no path.") if defined($config{protInbound});
	print STDERR "Full path MUST be specified. $filename has no path.\n";
        return '';
    }
    if ( open( FUU, $filename ) ) {
	binmode( FUU, ':raw' );
        while ( read( FUU, $bindata, 45 ) ) {
            $uuestr .= pack("u", $bindata);
        }
        close(FUU);
        $uuestr .= "end\r\r";
        return($uuestr);
    }
    else {
        w_log("Can't open \"$filename\"\: $!") if defined($config{protInbound});
	print STDERR "Can't open \"$filename\"\: $!\n";
        return('');
    }
}

sub find_free_filename($)
{
    local ($o_file) = @_;
    local ($o_fname, $o_ext);
    if ( $o_file =~ /^(.*)(\.[^\.\\\/]+)$/ ) {
       ($o_fname, $o_ext) = ($1, $2);
    } else {
       ($o_fname, $o_ext) = ($o_file, '');
    }
    local $o_i = 0;
    while (-e $o_file) {
	$o_file = sprintf("$o_fname%04x$o_ext", $o_i);
	$o_i++;
	if ($o_i > 65535) {
	    $o_file = $o_fname . $o_ext;
	}
    }
return $o_file;
}

1;
