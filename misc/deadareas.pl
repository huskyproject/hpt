#!/usr/bin/perl
#
# dead areas checker
# by roman korolyov
# rk@inetcomm.net / 2:5095/1.0
#
$DUPES="/home/fido/dupes/*.dph";        # filemask to dupebase
$EXCLUDE="/home/fido/config/deadareas.exclude"; #Exclude areas
$DEADTIME=30;                           # days before set to dead
$LOGFILE="/home/fido/log/deadareas.log";# logfile
$DEADFILE="/home/fido/log/dead.areas";

@month=("Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec");

open(EXCL,"$EXCLUDE");
while(<EXCL>) {
    chomp;
    $EXCAREA{lc($_)}=1;
}
close (EXCL);

open(LOG,">>$LOGFILE");
open(DEADF,">$DEADFILE");

@dps=< $DUPES >;
$curtime=time;

 ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
 if ( length($mday) < 2 ) { $mday="0".$mday; }
 if ( length($hour) < 2 ) { $hour="0".$hour; }
 if ( length($min) < 2  ) { $min ="0".$min ; }
 if ( length($sec) < 2  ) { $sec ="0".$sec ; }
 $logtime="$hour:$min:$sec $mday-$month[$mon]-".(1900+$year);

 print LOG "--- $logtime ---\n";
 foreach $i ( @dps ) {
    if ( length($i) > 1 ) {

($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat($i);
        $i=~m/\/(.+)\/(.+)\.dph/g;
        $fname=$2;
        if ( $curtime >= $mtime ) {
            if ( ( $curtime - $mtime ) > ($DEADTIME*24*60*60) ) {
                if ( $EXCAREA{lc($fname)} != 1 ) {
                    print LOG uc($fname)," dead for ",int(($curtime - $mtime)/60/60/24)," days\n";
                    print DEADF uc($fname)," ",int(($curtime - $mtime)/60/60/24),"\n";
                }
            }

        } else {
            print LOG uc($fname)," has future time\n";
        }
    }
 }
 ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
 if ( length($mday) < 2 ) { $mday="0".$mday; }
 if ( length($hour) < 2 ) { $hour="0".$hour; }
 if ( length($min) < 2  ) { $min ="0".$min ; }
 if ( length($sec) < 2  ) { $sec ="0".$sec ; }
 $logtime="$hour:$min:$sec $mday-$month[$mon]-".(1900+$year);

 print LOG "--- $logtime ---\n";

close (LOG);
close (DEADF);
