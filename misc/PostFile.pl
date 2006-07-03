#!/usr/bin/perl
# (c) Michael Dukelsky 2:5020/1042
#Here is a Perl script that posts messages of some specific size you define in
#the command line. You may run it this way
#
#PostFile <filename> <size in Kbytes>
#
#I wrote the script for myself. So you have to change the parameters of "hpt
#post" in the last cycle. Or you may make some of them command line arguments.
#

use strict;

my $origin="Moscpw, Russia";
my $subject="BinkD FAQ";
my $echoarea="BINKD";
my $from="Binkd Team";

my $fileNum = 1;
my $fileLen = 0;
my $outFileName = "@ARGV[0]".".$fileNum";
open(IN, "<@ARGV[0]") or die  "Cannot open the file @ARGV[0]: $!";
open(OUT, ">$outFileName") or die  "Cannot open the file $outFileName: $!";

while(<IN>)
{
    my $line = $_;
    $fileLen += do {use bytes; length;};
    if($fileLen < @ARGV[1] * 1024)
    {
        print OUT "$line";
    }
    else
    {
        close(OUT);
        $fileLen = 0;
        $fileNum++;
        $outFileName = "@ARGV[0]".".$fileNum";
        open(OUT, ">$outFileName") or die  "Cannot open the file $outFileName:
$!";
        print OUT "$line";
    }
}
close(IN);
close(OUT);

for(my $i = 1; $i <= $fileNum; $i++)
{
    $outFileName = "@ARGV[0]".".$i";
    my @args = ("hpt", "post", "-e", "$echoarea", "-nf", "\"$from\"",
                "-nt", "All", "-s", "\"$subject [$i/$fileNum]\"",
                "-o", "\"$origin\"", "-f", "loc", "-x", "$outFileName");
    system(@args);
}
