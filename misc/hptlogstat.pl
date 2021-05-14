#!/usr/bin/perl
#
# $Id$
#
# Authors:
# Yuriy Daybov (2:5029/42),
# Valery Kondakoff (2:5020/163),
# Michael Savin (2:5070/269).
# Code was based on original Michael Savin idea.
#
# Description:
# This script parses HPT logfile and produces echomail traffic,
# packet/bundles, messages posted by "hpt post" command and echoes
# throughput statistics for specified echoareas and specified period
# of time (in days). You can use '*' as simple wildcard to create
# statistics for more than one area.
# Areanames are case insensitive. Use -traffic key to sort echoes by
# traffic. All command line switches are optional. The order of command
# line switches is not important.
#
# Usage:
# Set $logname to point to your HPT logfile. Then call the script:
#
# hptlog_stats.pl [areaname_using_wildcard] [days] [-traffic]
#
# Examples:
# "hptlog_stats.pl ru.nncron 30" - create 30-day statistics for "RU.NNCRON"
# "hptlog_stats.pl 7" - create 7-day statistics for all the subscribed areas
# "hptlog_stats.pl 14 *win*" - create 14-day statistics for all echoareas
# with "win" in their names.
# "hptlog_stats.pl 1 -traffic" - sorted by traffic statistics for last day
# "hptlog_stats.pl" - create statistics for all subscribed groups using
# entire HPT log file etc...

use strict;
use warnings;
use Time::Local;

my $logname = "/home/mike/fido/log/hpt.log";

# this hash is used, when converting verbose months to numeral (Jan = 0)
my %months;
@months{qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec)} = (0..11);

# working with command line arguments
if($#ARGV > 2)
{
    print("Wrong command line arguments number\n");
    exit;
}

my ($traff, $period, $areaname);
foreach(@ARGV)
{
    if(/^-traffic$/)
    {
        $traff = 1
    }
    elsif(/^\d{1,4}$/ && !$period)
    {
        $period = $_
    }
    else
    {
        $areaname = $_
    }
}

my $date = time() - (24 * 60 * 60 * ($period - 1)) if $period;

# checking if the user enters "*" or "*.*" as areaname
my $long_stats = 1 if(!$areaname || $areaname =~ /^\*(\.\*)?$/);
$areaname ||= "*";
$areaname =~ s/\./\\./g;
$areaname =~ s/\*/\.*/g;

my ($last, $from, $posted, $bundles, $packets, %count);

open(LOG, "<", "$logname") or die "can't open $logname: $!";
while(<LOG>)
{
    if(/-{10}\s+\w+\s(.*),/)
    {
        $last = $1;
        if(!$from)
        {
            my $found = date_to_unixtime($1);
            $date ||= $found;
            $from = $1 if($found >= $date);
        }
        next;
    }
    if($from)
    {
        $count{"\L$1\E"} += $2 if(/echo area ($areaname) - (\d*)/i);
        if(/^5.*\s+posting msg.*area:\s+($areaname)/i)
        {
            my $area = $1;
            # remove possible "with subject: ..."
            $area =~ s/^(\S+).*$/$1/;
            if($area ne "netmail")
            {
                $count{"\L$area\E"}++;
                $posted++;
            }
        }
        $bundles++ if(/^6.*\s+bundle\s/);
        $packets++ if(/^7.*\s+pkt\:\s/);
    }
}
close LOG or die "Can't close $logname: $!";

# error checking
unless(%count)
{
    print "No messages in \"$areaname\": non existant areaname" .
          " or wrong period of days!\n";
    exit;
}

$period ||= int ((date_to_unixtime($last) - $date) /24 /60 /60 + 1);
print "\nEchomail traffic from \"$from\" to \"$last\" ";
printf "($period day%s).\n\n", ($period == 1) ? "" : "s";
print "Echoarea                       Posts\n";
print "------------------------------ -------\n";
my $all;
if($traff)
{
    foreach my $key (sort { $count{$b}<=>$count{$a} } keys %count)
    {
       $all += $count{$key};
       printf "%-30s %-6s\n", $key, $count{$key};
    }
}
else
{
    foreach my $key (sort keys %count)
    {
       $all += $count{$key};
       printf "%-25s %-6s\n", $key, $count{$key};
    }
}
print "------------------------------ -------\n";
print "Total messages:                $all\n";
print "Packets:                       $packets\n" if $long_stats;
print "Bundles:                       $bundles\n" if $long_stats;
print "(Auto)posted messages:         $posted\n" if $posted;
print "------------------------------ -------\n";
print "Total echoes processed:        ", scalar(keys %count),"\n";
print "------------------------------ -------\n";
print  "Average through-put per day:\n";
printf "        messages:              %.2f\n", $all/$period;
printf "        packets:               %.2f\n", $packets/$period if $long_stats;
printf "        bundles:               %.2f\n", $bundles/$period if $long_stats;
printf "        (auto)posted:          %.2f\n\n", $posted/$period if $posted;

# convert date in the format "04 May 2021" to unix time in seconds
sub date_to_unixtime
{
    $_[0] =~ /(\d{2})\s(\w{3})\s(\d{4})/;
    my ($day, $month, $year) = ($1, $2, $3);
    timelocal("59", "59", "23", $day, $months{$month}, $year);
}
