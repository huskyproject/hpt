#!/usr/bin/perl
#
# $Id$
#
# $Log$
# Revision 1.2  2002/01/27 14:38:17  stas
# Add the '-c' option (copy mode) and change temp & old file names.
#
#

$stopat = 5;
N: foreach (@ARGV) {
    help() if (/^-h$/);
    rushelp() if (/^-hr$/);
    $df=$1, next N if (/^-desc(.+)/);
    $ds=1,  next N if (/^-set$/);
    $na=1,  next N if (/^-na$/);
    $dl=1,  next N if (/^-d$/);
    $bk=1,  next N if (/^-b$/);
    $ns=1,  next N if (/^-ns$/);
    $nf=1,  next N if (/^-nf$/);
    $stopat=3, next N if (/^-nfa$/);
    $no=1,  next N if (/^-no$/);
    $nl=1,  next N if (/^-nl$/);
    $alst=$_ if (-f $_);
    $c=1, next if (/^-c$/);
}
help() unless ($alst);

$aold="$alst.old";
$anew="$alst".'.$$$';

open LIST, "<$alst" or die "Error open $alst";
open LOUT, ">$anew" or die "Error open temporary file";
readna() if ($df);

%echooptions = (
'-lr' => '\d+',
'-lw' => '\d+',
'-p' => '\d+',
'-mandatory' => '',
'-ccoff' => '',
'-$m' => '\d+',
'-nopack' => '',
'-killRead' => '',
'-keepUnread' => '',
'-a' => '\S+',
'-b' => '\S+',
'-g' => '\S+',
'-keepsb' => '',
'-tinysb' => '',
'-killsb' => '',
'-manual' => '',
'-dosfile' => '',
'-h' => '',
'-d' => '\".+\"',
'-nopause' => '',
'-DupeCheck' => '(off|move|del)',
'-DupeHistory' => '\d+',
'-nolink' => '',
'-debug' => '',
'-sbadd' => '',
'-sbign' => ''
);

print ":: Начинаем сортировку. Возможно это займет много времени.\n";
my @ml;

$ln=0;
foreach $line (<LIST>) {
   chomp $line;
   if (($type,$name,$file,$rest) = $line=~/^(\w+)\s+(\S+)\s+(\S+)\s+(.+)/i) {
      
      $rest=~s/\"(.*)\"/do{$_=$1, $_=~tr# #\x01#, '"'.$_.'"'}/eg;

      @res = (split /\s+/, $rest);
      map {tr/\x01/ /} @res;
      @opt = ();
      @lnk = ();

      for ($i=0, $rest=''; $i<=$#res; $i++){
                $ss = $res[$i];
                $ss=~s/\(.*\)//;
                ($opti) = (grep (/^\Q$ss/i, keys %echooptions));
                # check is not implemented yet
                $eo = $echooptions{$opti};
                if ($eo) {
                    push @opt, "$res[$i] $res[++$i]";
                } elsif ($opti) {
                    push @opt, $res[$i];
                } else {
                    if ($res[$i]=~/-(def|r|w|mn)/) {
                        $lnk[$#lnk].=' '.$res[$i];
                    } else {
                        push @lnk, $res[$i];
                    }
                }
      }
      # foreach (@opt) { print "$_\, " }; print "\n";

      $desc = (grep /^-d /, @opt)[0];
      @opt  = grep !/^-d /, @opt;
      if ($df and (!$desc or $ds)) {
         $ndesc = description(lc($name));
         $desc = "-d \"". $ndesc ."\"" if ($ndesc);
      }

      if ($no) {$rest = join " " ,@opt} else
               {$rest = join " " ,sort {$a cmp $b} @opt};
      if ($nl) {$links= join " " ,@lnk} else
               {$links= join " " ,sort {mysort()} @lnk};
      sub mysort {
          my ($i,$j);
          $i=$a; $j=$b;
          $i=~s/(\d+)/'0' x (5-length($1)) . $1/eg;
          $j=~s/(\d+)/'0' x (5-length($1)) . $1/eg;
          return $i cmp $j;
      }

      &max(1, $type);
      &max(2, $name);
      &max(3, $file);
      &max(4, $rest);
      &max(5, $desc);
      $lines[$ln] = [ (1, $type, $name, $file, $rest, $desc, $links) ];
   } else {
      $lines[$ln] = [ (0, $line) ];
   }
   print ".";
   $ln++;
}
print "\n";

sub max() {
        my ($i, $s);
        ($i, $s)=@_;
        if ($ml[$i]<length($s)) {
            $ml[$i]=length($s);
        }
}

if (!$ns) {
print ":: Сортируем список арий.\n";
CN: for ($i=0; $i<=$ln; $i++) {
        if ($lines[$i][0]) {
            for ($j=$i; $j<=$ln; $j++) {
                 if (!$lines[$j][0]) {
                     @part=@lines[$i..$j-1];
                     @part = sort {${$a}[2] cmp ${$b}[2]} @part;
                     @lines[$i..$j-1]=@part;
                     $i=$j;
                     next CN;
                 }
            }
        }
}
}

if (!$nf) { print ":: Выравниваем информацию.\n" } else
          { print ":: Объединяем информацию.\n" }
for ($i=0; $i<$ln; $i++) {
      @al = @{$lines[$i]};
      if ($al[0]) {
          $al[3] = 'passthrough' if ($al[3]=~/passthrough/i);
          if (!$nf) {
               for ($j=2; $j<=$stopat; $j++) {
                    $al[$j].=' ' x ( $ml[$j]-length($al[$j]) );
               }
          }
          # no desc
          if (($dl) and not ($al[5]=~/\w/) ) {
              $line = join ' ', (@al) [1,2,3,4,6];
          } else {
              $line = join ' ', (@al) [1,2,3,4,5,6];
          }
          $line =~ s/\s+$//;
      } else {
          $line = $al[1];
      }
      print LOUT "$line\n";
}

close LIST;
close LOUT;
rename($alst,$aold) unless ($bk || $c);
rename($anew,$alst) unless ($c);
print ":: Процесс завершен.\n";

sub readna() {
        open DESC, "<$df" or die "Error open $df";
        print ":: Читаем файл описаний арий.\n";
        foreach $line (<DESC>) {
           chomp $line;
           if ($na) {
                ($name,$tmp) = $line=~/(\S+)[\s\"]+(.+)/;
                $tmp=~s/[\s\"]+$//;
                $descript{lc($name)}=$tmp;
           } else {
             if ($line=~/(hold|down|),/i) {
                ($name,$tmp)=(split(/,/,$line))[1,2];
                $descript{lc($name)}=$tmp;
             }
           }
        }
}
sub description() {
    ($_)=@_;
    return $descript{$_} if ($descript{$_});
    # :: Здесь вы можете проставить свою реакцию на название арии ::
    # return 'Some CityCat echo...' if (/^ru\.list\.citycat/i);
    # return 'Some ExUSSR echo...'  if (/^su\./i);
    # return 'Some Russian echo...' if (/^ru\./i);
    # return 'Some private echo...' if (/^pvt\./i);
    return '';
}

sub help() {
        print "Husky areafile pretty formatter.\n";
        print "::  Copyleft (c) 2002, by Michael Savin, 2:5070/269.\n";
        print "::  \n";
        print "::  Use -hr option for russian help\n";
        print "::  \n";
        print "Usage: pretty.pl [-d] [-b] [-ns] [-nf[a]] [-no] [-nl] <[file]area.lst>\n";
        print "                 [-desc<echodesc> [-na] [-set]] [-n]\n\n";
        print "::  where:\n";
        print "::  -c     don't replace original file, formatted areafile saved with suffix '.$$$'\n";
        print "::  -d     place links & descriptions into same column\n";
        print "::  -b     don't backup original areafile\n";
        print "::  -ns    don't sort areatags\n";
        print "::  -nf    don't justify columns\n";
        print "::  -nfa   -nf + don't justify options & links\n";
        print "::  -no    don't sort options for area\n";
        print "::  -nl    don't sort links for area\n";
        print "::  -desc [-na] [-set]\n";
        print "::         add descriptions from comma-delimeted arealist\n";
        print "::         '-desc -na' - from 'FILEBONE.NA'-like file\n";
        print "::         '-desc -set' - replace existing descriptions\n";
        print "::  \n";
        print "::  This is test version!. You are notified :)\n";
        exit;
}

sub rushelp() {
        print "Usage: pretty.pl [-d] [-b] [-ns] [-nf[a]] [-no] [-nl] <areafile>\n";
        print "                 [-c] [-desc<echodesc> [-na] [-set]]\n\n";
        print "::  Ключ -d позволяет выравнивать в одну и ту же колонку линков и\n";
        print "::    дескрипшены. Если у вас мало дескрипшенов, но много линков\n";
        print "::    (как у 2:5080/102 ;-), то воспользуйтесь данным ключом.\n";
        print "::  Ключ -b запрещает делать backup.\n";
        print "::  Ключ -ns запрещает сортировать арии.\n";
        print "::    По умолчанию сортируются только арии, идущие друг за другом.\n";
        print "::  Ключ -nf запрещает выравнивание (с -nfa не выравниваются опции/линки).\n";
        print "::  Ключ -no запрещает сортировать опции.\n";
        print "::  Ключ -nl запрещает сортировать линков.\n";
        print "::  Ключ -c  оставляет исходный файл без изменений, новый записывается\n";
        print "::    в файл с расширением '$$$'\n";
        print "::  Ключ -desc позволяет добавлять описания арий из файла типа\n";
        print "::    echo5020.lst. Если вдобавок установлена опция -na, то описания\n";
        print "::    будут браться из файла стандартного для hpt формата (FILEBONE.NA).\n";
        print "::    Можно в принудительном порядке проставлять описания, для этого\n";
        print "::    используйте ключ -set.\n";
        print "::  Example 0: pretty.pl areas.lst\n";
        print "::  Example 1: pretty.pl -descD:\\files\\Xofcelist\\echo5020.lst\n";
        print "::                       -set -no -nl -ns areas.lst\n";
        print "::  Внимание! Данная версия тестовая. Будьте осторожны.\n";
        exit;
}
