#! /usr/bin/perl
use strict;
# Display outbound summary for every link
# for which there is anything in the outbound
# Created by Pavel Gulchouck 2:463/68@fidonet
# Fixed by Stas Degteff 2:5080/102@fidonet
# Modified by Michael Dukelsky 2:5020/1042@fidonet
# version 1.0

# Only one FTN zone is supported

###### Configuration starts here #####
my $zone = 2;
my $outbound="S:/MAIL/out/OUTFILES";
###### Configuration ends here #####

chdir( $outbound );
my @files=<*.[IiCcDdFfHh][Ll][Oo]>;
push @files, <*.[IiCcDdOoHh][Uu][Tt]>;
push @files, <*.[Pp][Nn][Tt]/*.[IiCcDdFfHh][Ll][Oo]>;
push @files, <*.[Pp][Nn][Tt]/*.[IiCcDdOoHh][Uu][Tt]>;

my (%ctime, %netmail, %echomail, %files);
foreach my $file (@files)
{
    my $node=unbso($file);
    my ($size, $atime, $mtime, $ctime) = (stat($file))[7..10];
    if (!defined($ctime{$node}) || $ctime<$ctime{$node})
    {
        $ctime{$node} = $ctime if $ctime;
    }
    if ($file =~ /ut$/)
    {
        $netmail{$node} += $size;
        next;
    }
    # unix, read only -> ignore *.bsy
    next unless open(F, "<$file");
    while (<F>)
    {
        s/\r?\n$//s;
        s/^[#~^]//;
        next unless ($size, $ctime) = (stat($_))[7,10];
        if (/[0-9a-f]{8}\.(su|mo|tu|we|th|fr|sa)[0-9a-z]$/i)
        {
            if (!defined($ctime{$node}) || $ctime<$ctime{$node})
            {
                $ctime{$node} = $ctime;
            }
            $echomail{$node} += $size;
        }
        else
        {
            $files{$node} += $size;
        }
    }
    close(F);
}
print <<EOF;
+------------------+--------+-----------+-----------+-----------+
|       Node       |  Days  |  NetMail  |  EchoMail |   Files   |
+------------------+--------+-----------+-----------+-----------+
EOF
foreach my $node (sort nodesort keys %ctime)
{
    my $format = "| %-16s |%7u |" .
                 niceNumberFormat($netmail{$node}) . " |" .
                 niceNumberFormat($echomail{$node}) . " |" .
                 niceNumberFormat($files{$node}) . " |\n";
    printf "$format",
           $node, (time()-$ctime{$node})/(24*60*60),
           niceNumber($netmail{$node}),
           niceNumber($echomail{$node}),
           niceNumber($files{$node});
}
print "+------------------+--------+-----------+-----------+-----------+\n";
exit(0);

sub nodesort
{   my ($az, $an, $af, $ap, $bz, $bn, $bf, $bp);
    if ($a =~ /(\d+):(\d+)\/(\d+)(?:\.(\d+))?$/)
    {
        ($az, $an, $af, $ap) = ($1, $2, $3, $4);
    }
    if ($b =~ /(\d+):(\d+)\/(\d+)(?:\.(\d+))?$/)
    {
        ($bz, $bn, $bf, $bp) = ($1, $2, $3, $4);
    }
    return ($az<=>$bz) || ($an<=>$bn) || ($af<=>$bf) || ($ap<=>$bp);
}

sub unbso
{
    my ($file) = @_;
    if ($file =~ /([0-9a-f]{4})([0-9a-f]{4})\.pnt\/([0-9a-f]{8})/i)
    {
        return sprintf "%u:%u/%d.%d", $zone, hex("0x$1"), hex("0x$2"), hex("0x$3");
    } 
    elsif ($file =~ /([0-9a-f]{4})([0-9a-f]{4})/i)
    {
        return sprintf "%u:%u/%d", $zone, hex("0x$1"), hex("0x$2");
    }
}

sub niceNumber
{
    my ($num) = @_;
    # Less than 1 Mb
    if ($num < 1048576)
    {
        return $num;
    }
    # Between 1 Mb and 1 Gb
    elsif ($num >= 1048576 && $num < 1073741824)
    {
        return $num/1048576;
    }
    # More than 1 Gb
    else
    {
        return $num/1073741824;
    }
}

sub niceNumberFormat
{
    my ($num) = @_;
    return "%9u " if ($num < 1048576);

    my $len = length(sprintf "%4.4f", niceNumber($num));
    return ($len < 9 ? " " x (9 - $len) . "%4.4f" : "%4.4f") . 
           ($num < 1073741824 ? "M" : "G");
}
