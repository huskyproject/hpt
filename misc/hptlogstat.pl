#!/usr/bin/perl
#
# Author:
# Valery Kondakoff (2:5020/163).
# Code was based on original Michael Savin (2:5070/269) idea.
#
# Description:
# This script parse HPT logfile and produce echomail traffic statistics
# for specified echoareas and specified period of time (in days). You can
# use '*' as simple wildcard to create statistics for more than one area.
# Areanames are case insensitive.
#
# Usage:
# Set $logname to point to your HPT logfile. Then call this script:
# hptlog_stat.pl [areaname_using_wildcard] [days]
# or
# hptlog_stat.pl [days] [areaname_using_wildcard]
# Both command line arguments are optional.
#
# Examples:
# "hptlog_stat.pl ru.nncron 30" - create 30-day statistics for "RU.NNCRON"
# "hptlog_stat.pl 7" - create 7-day statistics for all the subscribed areas
# "hptlog_stat.pl 14 *win*" - create 14-day statistics for all echoareas
# with "win" in their names.
# "hptlog_stat.pl" - create statistics for all subscribed groups using
# entire HPT log file etc...

$logname = "/fido/log/hpt.log";

sub usage {
print <<USAGETEXT;
hpt log statistics (c) Valery Kondakoff (2:5020/163)
Code was based on original Michael Savin (2:5070/269) idea.

USAGE:
       hptlog_stat.pl [areatag_mask] [days]
       hptlog_stat.pl -h

USAGETEXT
exit;
}

if ( $ARGV[0] =~ /-[hH]/ ) { &usage; }

# working with command line arguments
if ($#ARGV > 1) {
    print("Wrong command line arguments number. Call with '-h' option for help\n");
    exit;
}

foreach (@ARGV) {
    if(/^\d{1,4}$/ && !$period) {
        $period = $_;
    } else {
        $areaname = $_;
    }
    #~ print "debug: inside foreach $period $areaname\n";
}
$period ? ($days = calculate_date($period)) : ($days = ".*");
$areaname = "*" unless $areaname;
$areaname =~ s/\*/.*/g;

open(LOG, "<$logname") || die "can't open $logname: $!";
while (<LOG>) {
    $from = $1 if /-{10}\s+\w+\s($days),/ && !$from;
    $last = $1 if /-{10}\s+\w+\s(.*),/;
    $count{"\L$1"} += $2 if $from && (/echo area ($areaname) - (\d*)/i);
}
# error checking - if we can find the day specified in log file
unless($from) {
    print "Can't find \"$days\" messages in your HPT log!\n";
    exit;
}
# error checking - if specified area exists
unless(%count) {
    print "Can't find \"$areaname\" areaname in your HPT log!\n";
    exit;
}
close LOG || die "can't close $logname: $!";;

print "\nEchomail traffic from \"$from\" to \"$last\".\n";
print "------------------------- ------\n";
foreach $key (sort keys %count) {
    $all += $count{$key};
    printf "%-25s %-6s\n", $key, $count{$key};
}
print "------------------------- ------\n";
print "Messages summary:         $all\n";

# calculating real date (like "20 Jan") from command line argument
sub calculate_date {
    $now_string = localtime(time() - (24 * 60 * 60 * $_[0]));
    $now_string =~ /^\w+\s(\w+)\s(\s?\d+).*(\d\d)$/;
    $day = sprintf("%02d", $2);
    return("$day $1 $3");
}
