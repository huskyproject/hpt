#!/usr/bin/perl
#
 
# makeavl.pl&readlist.pm by Alexander Reznikov 2:4600/220@fidonet, 
#                                              99:2003/110@webnet, 
#                                              homebrewer@yandex.ru
#
#
# Этот скрипт предназначен для создания полного списка всех эх, доступных
# на узле. В качестве исходных данных используются списки эх аплинков в формате
# EchoList. Также опционально может быть использован свой собственных эхолист
# в том же формате. В случае hpt его можно создать при помощи скрипта 
# fconf2na.pl. Также скрипт пытается брать описания эх из echolist.txt 
# (файлэха ECHOLIST) и echo5020.lst, если они есть в текущей директории.

# Текущий эхолист в формате Echolist,
# если не задан (закомментирован) - не используется
# Его можно получить при помощи fidoconfig/fconf2na.pl
$echolist = 'echolist.fe';

# имя результирующего списка эх "без дупов"
$avlname = '11f800dc.fwd';

# Список avail-файлов в фомате Echolist, из которых формируется результирующий 
# список
@fwdlists = ('fwd126.txt', 'fwd113.txt', 'fwd103.txt');

#########
use readlist;
InitEchoList();

read_echolist($echolist) if (defined $echolist)&&($echolist ne '');

foreach $i (@fwdlists)
{
 read_echolist($i);
}

open FILE, ">$avlname";

foreach $i (sort keys(%echo))
{
 $descr = GetEchoListDescr($i) || $echo{$i} || '';
# $descr = $echo{$i} if length($descr)==0;

 $descr =~ tr/Н/H/;

 print FILE "$i".(length($descr)>0? " $descr": '')."\n";
}

close(FILE);

sub read_echolist
{
 my $filename = shift;
 if (!open FILE, "<$filename")
 {
  warn("Can not open \'$filename\' ($!)\n");
  return 0; 
 }

 my ($echoid, $descr);

 while (<FILE>)
 {
  chomp;

  if (/^([^ ]+)\s*\"?(.*?)\"?$/)
  {
   $echoid = uc($1);
   $descr = $2;

   $echo{$echoid} = $descr if (!exists $echo{$echoid})||(length($echo{$echoid})==0);
  }
 }
 close(FILE);
 return 1;
}
