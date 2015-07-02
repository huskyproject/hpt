#!/usr/bin/perl
#
# Display outbound summary for every link
# for which there is anything in the outbound
# Created by Pavel Gulchouck 2:463/68@fidonet
# Fixed by Stas Degteff 2:5080/102@fidonet
# Modified by Michael Dukelsky 2:5020/1042@fidonet
# version 2.1
# It is free software and license is the same as for Perl,
# see http://dev.perl.org/licenses/
#

##### There is nothing to change below this line #####
use File::Spec;
use File::Find;
use Config;
use strict;
use warnings;

my ($fidoconfig, $OS, $module, $defZone, 
    $defOutbound, @dirs, @boxesDirs, @asoFiles,
    %ctime, %netmail, %echomail, %files);
my $commentChar = '#';
my $Mb = 1024 * 1024;
my $Gb = $Mb * 1024;

sub usage
{
    print <<USAGE;

    The script showold.pl prints out to STDOUT how much netmail, echomail 
    and files are stored for every link in the outbound and fileboxes and 
    how long they are stored.

    If FIDOCONFIG environment variable is defined, you may use the script
    without arguments, otherwise you have to supply the path to fidoconfig
    as an argument.

    Usage:
        perl showold.pl
        perl showold.pl <path to fidoconfig>

    Example:
        perl showold.pl M:\\mail\\Husky\\config\\config
USAGE
    exit 1;
}

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
    my ($file, $dir) = @_;
    my $zone;
    if($dir =~ /\.([0-9a-f])([0-9a-f])([0-9a-f])$/i)
    {
        $zone = hex("$1")*256 + hex($2)*16 + hex($3);
    }
    else
    {
        $zone = $defZone;
    }
    if ($file =~ /([0-9a-f]{4})([0-9a-f]{4})\.pnt\/([0-9a-f]{8})/i)
    {
        return sprintf "%u:%u/%d.%d", $zone, hex("$1"), hex("$2"), hex("$3");
    } 
    elsif ($file =~ /([0-9a-f]{4})([0-9a-f]{4})/i)
    {
        return sprintf "%u:%u/%d", $zone, hex("$1"), hex("$2");
    }
    else
    {
        return "";
    }
}

sub unaso
{
    my ($file) = @_;
    if($file =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/)
    {
        if($4 == 0)
        {
            return "$1:$2\/$3";
        }
        else
        {
            return "$1:$2\/$3\.$4";
        }
    }
    else
    {
        return "";
    }
}

sub unbox
{
    my ($dir) = @_;
    if($dir =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)(?:\.h)?$/i)
    {
        return $4 == 0 ? "$1:$2\/$3" : "$1:$2\/$3\.$4";
    }
    else
    {
        return "";
    }
}

sub niceNumber
{
    my ($num) = @_;
    return ($num < $Mb ? $num : ($num >= $Mb && $num < $Gb ? $num/$Mb : $num/$Gb));
}

sub niceNumberFormat
{
    my ($num) = @_;
    return "%9u " if ($num < $Mb);

    my $len = length(sprintf "%4.4f", niceNumber($num));
    return ($len < 9 ? " " x (9 - $len) . "%4.4f" : "%4.4f") . 
           ($num < $Gb ? "M" : "G");
}

sub normalize
{
    my ($path) = @_;
    return $path if($OS eq 'UNIX');
    my ($vol, $d, $f) = File::Spec->splitpath($path);
    my @d = File::Spec->splitdir($d);
    $d = File::Spec->catdir(@d);
    return File::Spec->catpath($vol, $d, $f);
}

sub selectOutbound
{
    if (-d $File::Find::name && $File::Find::name =~ /\.[0-9a-f]{3}$/i)
    {
        push(@dirs, normalize($File::Find::name));
    }
}

sub listOutbounds
{
    my ($dir) = @_;
    my ($volume, $directories, $file) = File::Spec->splitpath(normalize($dir));
    if($file eq "")
    {
        my @dirs = File::Spec->splitdir($directories);
        $file = pop @dirs;
        $directories = File::Spec->catdir(@dirs);
    }
    my $updir=File::Spec->catpath($volume, $directories, "");
    @dirs=($dir);

    find(\&selectOutbound, $updir);
    return @dirs;
}

sub selectFileInASO
{
    if (-f $File::Find::name && -s $File::Find::name &&
        ($File::Find::name =~ /\d+\.\d+\.\d+\.\d+\.[icdoh]ut$/i ||
         $File::Find::name =~ /\d+\.\d+\.\d+\.\d+\.(su|mo|tu|we|th|fr|sa)[0-9a-z]$/i))
    {
        push(@asoFiles, normalize($File::Find::name));
    }
}

sub listFilesInASO
{
    @asoFiles = ();
    find(\&selectFileInASO, $defOutbound);
    return @asoFiles;
}

sub selectFileBoxes
{
    if (-d $File::Find::name && $File::Find::name =~ /\d+\.\d+\.\d+\.\d+(?:\.h)?$/i)
    {
        push(@boxesDirs, normalize($File::Find::name));
    }
}

sub listFileBoxes
{
    my ($dir) = @_;
    find(\&selectFileBoxes, $dir);
    return @boxesDirs;
}

sub allFilesInBSO
{
    my ($dir) = @_;
    chdir($dir);
    my @files = <*.[IiCcDdFfHh][Ll][Oo]>;
    push @files, <*.[IiCcDdOoHh][Uu][Tt]>;
    push @files, <*.[Pp][Nn][Tt]/*.[IiCcDdFfHh][Ll][Oo]>;
    push @files, <*.[Pp][Nn][Tt]/*.[IiCcDdOoHh][Uu][Tt]>;
    return if(@files == 0);

    foreach my $file (@files)
    {
        my $node=unbso($file, $dir);
        next if($node eq "");
        my ($size, $atime, $mtime, $ctime) = (stat($file))[7..10];
        next if($size == 0);
        if (!defined($ctime{$node}) || $ctime < $ctime{$node})
        {
            $ctime{$node} = $ctime if $ctime;
        }
        if ($file =~ /ut$/i)
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
            next unless ($size, $ctime) = (stat($_))[7, 10];
            next if($size == 0);
            if (/[0-9a-f]{8}\.(su|mo|tu|we|th|fr|sa)[0-9a-z]$/i)
            {
                if (!defined($ctime{$node}) || $ctime < $ctime{$node})
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
}

sub allFilesInASO
{
    chdir($defOutbound);
    my @files = listFilesInASO();
    return if(@files == 0);

    foreach my $file (@files)
    {
        my $node=unaso($file);
        next if($node eq "");
        my ($size, $ctime) = (stat($file))[7, 10];
        next if($size == 0);
        if (!defined($ctime{$node}) || $ctime < $ctime{$node})
        {
            $ctime{$node} = $ctime if $ctime;
        }
        if ($file =~ /ut$/i)
        {
            $netmail{$node} += $size;
        }
        else
        {
            $echomail{$node} += $size;
        }
    }
}

sub allFilesInFileBoxes
{
    my ($dir) = @_;
    my $node = unbox($dir);
    next if($node eq "");
    chdir($dir);
    my @files = <*.[IiCcDdOoHh][Uu][Tt]>;
    push @files, <*.[Ss][Uu][0-9a-zA-Z]>;
    push @files, <*.[Mm][Oo][0-9a-zA-Z]>;
    push @files, <*.[Tt][Uu][0-9a-zA-Z]>;
    push @files, <*.[Ww][Ee][0-9a-zA-Z]>;
    push @files, <*.[Tt][Hh][0-9a-zA-Z]>;
    push @files, <*.[Ff][Rr][0-9a-zA-Z]>;
    push @files, <*.[Ss][Aa][0-9a-zA-Z]>;
    return if(@files == 0);

    foreach my $file (@files)
    {
        my ($size, $atime, $mtime, $ctime) = (stat($file))[7..10];
        next if($size == 0);
        if (!defined($ctime{$node}) || $ctime < $ctime{$node})
        {
            $ctime{$node} = $ctime if $ctime;
        }

        if ($file =~ /ut$/i)
        {
            $netmail{$node} += $size;
            next;
        }
        elsif ($file =~ /\.(su|mo|tu|we|th|fr|sa)[0-9a-z]$/i)
        {
            # Both BSO and ASO style echomail bundles are handled here
            if (!defined($ctime{$node}) || $ctime < $ctime{$node})
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
}


# stripSpaces(@array) returns the array, every element of which
# is stripped of heading and trailing white spaces.
sub stripSpaces
{
    my @arr = @_;
    foreach (@arr)
    {
        next unless $_;
        s/^\s+//;
        s/\s+$//;
    }
    return @arr;
}

# stripQuotes(@array) returns the array, every element of which
# is stripped of heading and trailing double quote character.
sub stripQuotes
{
    my @arr = @_;
    foreach (@arr)
    {
        next unless $_;
        s/^\"(.+)\"$/$1/;
    }
    return @arr;
}

# expandVars($expression) executes commands in backticks
# found in the $expression, substitutes environment
# variables by their values and returns the resulting string
sub expandVars
{
    my ($expr) = stripSpaces(@_);
    my ($result, $left, $cmd, $var, $remainder);

    if ($OS eq 'UNIX' or $OS eq 'OS/2')
    {
        # execute commands in backticks
        $cmd = 1;
        $result = "";
        while ($cmd)
        {
            ($left, $cmd, $remainder) = split /`/, $expr, 3;
            if ($cmd)
            {
                $result .= $left . eval('`' . $cmd . '`');
                $result =~ s/[\r\n]+$//;
                last unless $remainder;
                $expr = $remainder;
            }
            else
            {
                $result .= $expr;
            }
        }
        $expr = $result;
    }

    # substitute environment variables by their values
    $var = 1;
    $result = "";
    while ($var)
    {
        ($left, $var, $remainder) = split /[\[\]]/, $expr, 3;
        if ($var)
        {
            $result .=
              $left
              . (
                 lc($var) eq "module"
                 ? "module"
                 : ($ENV{$var} ? $ENV{$var} : ""));
            last unless $remainder;
            $expr = $remainder;
        }
        else
        {
            $result .= $expr;
        }
    }
    return $result;
}

# cmpPattern($string, $pattern) compares $string with $pattern
# and returns boolean result of the comparison. The pattern
# may contain wildcard caracters '?' and '*'.
sub cmpPattern
{
    my ($string, $pattern) = @_;
    $pattern =~ s/\?/./g;
    $pattern =~ s/\*/.*/g;
    return $string =~ /^$pattern$/;
}

sub boolExpr
{
    my ($expr, $ifLevel, $moduleIfLevel) = @_;
    my ($result, $not, $left, $right);
    $result = $not = "";

    if ($expr =~ /^not\s+(.+)$/i)
    {
        $not = 1;
        $expr = $1;
    }

    if ($expr =~ /^(.+)==(.+)$/)
    {
        ($left, $right) = stripSpaces($1, $2);
        if (lc($left) eq "module")
        {
            if ($result = lc($right) eq "hpt")
            {
                $module = "hpt";
                $moduleIfLevel = $ifLevel;
            }
            elsif ($result = lc($right) eq "htick")
            {
                $module = "htick";
                $moduleIfLevel = $ifLevel;
            }
        }
        elsif (lc($right) eq "module")
        {
            if ($result = lc($left) eq "hpt")
            {
                $module = "hpt";
                $moduleIfLevel = $ifLevel;
            }
            elsif ($result = lc($left) eq "htick")
            {
                $module = "htick";
                $moduleIfLevel = $ifLevel;
            }
        }
        else
        {
            $result = $left eq $right;
        }
    }
    elsif ($expr =~ /^(.+)!=(.+)$/)
    {
        ($left, $right) = stripSpaces($1, $2);
        $result = $left ne $right;
    }
    elsif ($expr =~ /^(.+)=~(.+)$/)
    {
        $result = cmpPattern(stripSpaces($1, $2));
    }
    elsif ($expr =~ /^(.+)!~(.+)$/)
    {
        $result = not cmpPattern(stripSpaces($1, $2));
    }

    return $not ? not $result : $result;
}

# stripComment(@lines) strips a comment from @lines and returns the array
sub stripComment
{
    my @arr = @_;
    foreach (@arr)
    {
        next unless $_;
        next if s/^$commentChar.*$//;
        s/\s+$commentChar\s.*$//;
    }
    return @arr;
}

# parseIf($line, \@condition) parses $line for conditional operators
# and returns 1 if the line should be skipped else 0.
sub parseIf
{
    my ($line, $rCondition, $ifLevel, $moduleIfLevel) = @_;

    return 1 if $line eq "";

    if ($line =~ /^if\s+(.+)$/i)
    {
        $ifLevel++;
        return 1 if @$rCondition and not $$rCondition[-1];
        push @$rCondition, boolExpr(expandVars($1), $ifLevel, $moduleIfLevel);
        return 1;
    }
    elsif ($line =~ /^ifdef\s+(.+)$/i)
    {
        $ifLevel++;
        return 1 if @$rCondition and not $$rCondition[-1];
        my $var = expandVars($1);
        push @$rCondition, ($var ? exists $ENV{$var} : 0);
        return 1;
    }
    elsif ($line =~ /^ifndef\s+(.+)$/i)
    {
        $ifLevel++;
        return 1 if @$rCondition and not $$rCondition[-1];
        my $var = expandVars($1);
        push @$rCondition, ($var ? not exists $ENV{$var} : 1);
        return 1;
    }
    elsif ($line =~ /^elseif\s+(.+)$/i or $line =~ /^elif\s+(.+)$/i)
    {
        return 1 if @$rCondition != $ifLevel;
        $moduleIfLevel = 0 if $moduleIfLevel and $moduleIfLevel == $ifLevel;
        pop @$rCondition;
        push @$rCondition, boolExpr(expandVars($1), $ifLevel, $moduleIfLevel);
        return 1;
    }
    elsif ($line =~ /^else$/i)
    {
        return 1 if @$rCondition != $ifLevel;
        $moduleIfLevel = 0 if $moduleIfLevel and $moduleIfLevel == $ifLevel;
        push @$rCondition, not pop(@$rCondition);
        return 1;
    }
    elsif ($line =~ /^endif$/i)
    {
        $moduleIfLevel = 0 if $moduleIfLevel and $moduleIfLevel == $ifLevel;
        pop @$rCondition if @$rCondition == $ifLevel--;
        return 1;
    }

    return 1 if $ifLevel and not $$rCondition[-1];
    return 0;
}

# findTokenValue($token, $tokenFile) returns ($value, $tokenFile),
# where $value is the value of the $token in husky fidoconfig.
# Search of the token is started in the file with the full path
# $tokenFile in the argument and in all included files and the returned
# $tokenFile is the file where the token was found.
# If the token was not found, $value is an empty string,
# if the token was found but with empty value, then
# a string "on" is returned as $value.
sub findTokenValue
{
    my ($token, $tokenFile) = @_;
    my ($value, @lines, @condition, $ifLevel, $moduleIfLevel);
    $value = "";
    $ifLevel = $moduleIfLevel = 0;

    ($tokenFile) = stripQuotes(stripSpaces($tokenFile));

    open(FIN, "<", $tokenFile) or die("$tokenFile: $!");
    @lines = <FIN>;
    close FIN;

    foreach my $line (stripSpaces(stripComment(@lines)))
    {
        next if parseIf($line, \@condition, $ifLevel, $moduleIfLevel);

        $line = expandVars($line);

        if ($line =~ /^$token\s+(.+)$/i)
        {
            ($value) = stripSpaces($1);
            last;
        }
        elsif ($line =~ /^$token$/i)
        {
            $value = "on";
            last;
        }
        elsif ($line =~ /^include\s+(.+)$/i)
        {
            my $newTokenFile;
            ($value, $newTokenFile) = findTokenValue($token, $1);
            if ($value and $newTokenFile)
            {
                $tokenFile = $newTokenFile;
                last;
            }
        }
        elsif ($line =~ /^set\s+(.+)$/i)
        {
            my ($var, $val) = stripSpaces(split(/=/, $1));
            ($val) = stripQuotes($val);
            $val ? ($ENV{$var} = $val) : delete $ENV{$var};
        }
        elsif ($line =~ /^commentChar\s+(\S)$/i)
        {
            $commentChar = $1;
        }
    } ## end foreach my $line (@lines)
    return ($value, $tokenFile);
} ## end sub findTokenValue

# searchTokenValue($token, $tokenFile)
sub searchTokenValue
{
    my ($token, $tokenFile) = @_;
    $commentChar = '#';
    return findTokenValue($token, $tokenFile);
}

# isOn($value) returns true if the $value is the string representing "true"
# according to husky fidoconfig rules
sub isOn
{
    my ($val) = @_;
    return 1 if($val eq "1" or lc($val) eq "yes" or lc($val) eq "on");
    return 0;
}


###################### The main program starts here ##########################

$fidoconfig = $ENV{FIDOCONFIG} if defined $ENV{FIDOCONFIG};

if ((@ARGV == 1 && $ARGV[0] =~ /^(-|--|\/)(h|help|\?)$/i) || (!defined($fidoconfig) && @ARGV != 1))
{
    usage();
}

$fidoconfig = $ARGV[0] if(!defined($fidoconfig));
if (!(-f $fidoconfig && -s $fidoconfig))
{
    print "\n\'$fidoconfig\' is not fidoconfig\n";
    usage();
}

unless ($OS = $^O)
{
    $OS = $Config::Config{'osname'};
}

if ($OS =~ /^MSWin/i)
{
    $OS = 'WIN';
}
elsif ($OS =~ /^dos/i)
{
    $OS = 'DOS';
}
elsif ($OS =~ /^os2/i)
{
    $OS = 'OS/2';
}
elsif ($OS =~ /^VMS/i or $OS =~ /^MacOS/i or $OS =~ /^epoc/i or $OS =~ /NetWare/i)
{
    die("$OS is not supported\n");
}
else
{
    $OS = 'UNIX';
}
$ENV{OS} = $OS;
$ENV{$OS} = $OS;

#### Read fidoconfig ####
my ($address, $path, $fileBoxesDir);
$fidoconfig = normalize($fidoconfig);

my $separateBundles;
($separateBundles, $path) = searchTokenValue("SeparateBundles", $fidoconfig);
die "\nSeparateBundles mode is not supported\n" if(isOn($separateBundles));

($address, $path) = searchTokenValue("address", $fidoconfig);
$defZone = $1 if($address ne "" && $address =~ /^(\d+):\d+\/\d+(?:\.\d+)?(?:@\w+)?$/);
defined($defZone) or die "\nYour FTN address is not defined or has a syntax error\n";

($fileBoxesDir, $path) = searchTokenValue("FileBoxesDir", $fidoconfig);
if($fileBoxesDir ne "")
{
    -d $fileBoxesDir or die "\nfileBoxesDir \'$fileBoxesDir\' is not a directory\n";
    $fileBoxesDir = normalize($fileBoxesDir);
}

($defOutbound, $path) = searchTokenValue("Outbound", $fidoconfig);
$defOutbound ne "" or die "\nOutbound is not defined\n";
-d $defOutbound or die "\nOutbound \'$defOutbound\' is not a directory\n";
$defOutbound = normalize($defOutbound);

@dirs = listOutbounds($defOutbound);
@boxesDirs = listFileBoxes($fileBoxesDir) if($fileBoxesDir ne "");

allFilesInASO();

foreach my $dir (@dirs)
{
    allFilesInBSO($dir);
}

foreach my $dir (@boxesDirs)
{
    allFilesInFileBoxes($dir);
}

print <<EOF;
+------------------+--------+-----------+-----------+-----------+
|       Node       |  Days  |  NetMail  |  EchoMail |   Files   |
+------------------+--------+-----------+-----------+-----------+
EOF
foreach my $node (sort nodesort keys %ctime)
{
    $netmail{$node}  = 0 if(!defined $netmail{$node});
    $echomail{$node} = 0 if(!defined $echomail{$node});
    $files{$node}    = 0 if(!defined $files{$node});
    my $format = "| %-16s |%7u |" .
                 niceNumberFormat($netmail{$node}) . " |" .
                 niceNumberFormat($echomail{$node}) . " |" .
                 niceNumberFormat($files{$node}) . " |\n";
    printf $format,
           $node, (time()-$ctime{$node})/(24*60*60),
           niceNumber($netmail{$node}),
           niceNumber($echomail{$node}),
           niceNumber($files{$node});
}
print "+------------------+--------+-----------+-----------+-----------+\n";
exit(0);
