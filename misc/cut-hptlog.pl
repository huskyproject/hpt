#!/usr/bin/perl

# script for cutting a hpt's log-file
#
# (c)2002 sven(2:5030/1346)

use Time::Local;

$templog='/tmp/worklog.tmp';

if ( $#ARGV < 1 )
{   print "syntax is:    cut-hptlog.pl /var/fido/logs/hpt.log 14\n";
    print "\n";
    print "where first parametr is FULL path to hpt's log-file,\n";
    print "and second - is a number of days ";
    print "what information in log will be saved\n";
    <>;
    exit;
};
die "Logfile ($ARGV[0]) not found" unless (-f $ARGV[0]);

$saveday = $ARGV[1];
$keepit=0;

($x,$x,$x,$day,$mon,$year,$x,$x,$x)=localtime(time()-$saveday*24*60*60);
$save = timelocal(0,0,0,$day,$mon,$year);
($x,$x,$x,$day,$mon,$year,$x,$x,$x)=localtime(time());

open OLDLOG,$ARGV[0] || die "$ARGV[0] not found! :(";
open NEWLOG,'>'.$templog || die "Cannot create temp file ($templog)! :(";

while (<OLDLOG>)
{
   if (/\A----------\s+\S+\s+(\d+)\s+(\w+)\s+(\d+)/)
   {
        my $lday=$1;
        my %monthnum = (
        'Jan' => 0,
        'Feb' => 1,
        'Mar' => 2,
        'Apr' => 3,
        'May' => 4,
        'Jun' => 5,
        'Jul' => 6,
        'Aug' => 7,
        'Sep' => 8,
        'Oct' => 9,
        'Nov' => 10,
        'Dec' => 11,);
        my $lmon=$monthnum{$2};
        my $lyear=$3+100;
        my $ldate = timelocal(0,0,0,$lday,$lmon,$lyear);
        if ($ldate >= $save) { print NEWLOG; $keepit = 1; }
        else {$keepit = 0};
    }
    else { if ($keepit == 1) {print NEWLOG}};
}

%monthnum = (
0  => 'Jan',
1  => 'Feb',
2  => 'Mar',
3  => 'Apr',
4  => 'May',
5  => 'Jun',
6  => 'Jul',
7  => 'Aug',
8  => 'Sep',
9  => 'Oct',
10 => 'Nov',
11 => 'Dec',);

print NEWLOG "\n";
printf NEWLOG "---------- Число: %02d %s %02d Лог обрезан нахрен!\n",
              $day,$monthnum{$mon},$year-100;
print NEWLOG "\n";

close OLDLOG;
close NEWLOG;
rename $templog, $ARGV[0];

print "File: $ARGV[0] is succesfully cutted.\n";
