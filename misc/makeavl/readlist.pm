### readlist.pm by Alexander Reznikov, 2:4600/220@fidonet,
###                                    99:2003/110@webnet, 
###                                    homebrewer@yandex.ru
###
###
### Загружает описания эх из echolist.txt и echo5020.lst 
### echolist.txt можно найти в файлэхе ECHOLIST (echolist.zip)
###
package readlist;

require Exporter;

@ISA = qw(Exporter);
@EXPORT = qw(InitEchoList DeInitEchoList GetEchoListDescr GetMaxDescr);

my(%areas);

sub GetMaxDescr
{
 my $d1 = shift;
 my $d2 = shift;

 return $d1 if length($d1)>length($d2);
 return $d2;
}

sub GetEchoListDescr
{
 return $areas{uc(shift)};
}

sub DeInitEchoList
{
 undef(%areas);
}

sub InitEchoList
{
 DeInitEchoList();

 my($echotag, $descr);

 if (open(ECHOLISTFH, "<echolist.txt"))
 {
  while(<ECHOLISTFH>)
  {
   chomp;
   if (/^\s*\,\s*([^ ,]+)\,\s*(.*)$/o)
   {
    $echotag = uc($1);
    $descr = $2;
  
    $areas{$echotag} = GetMaxDescr($descr, $areas{$echotag});
   }
  }
 close(ECHOLISTFH);
 }
 
 if (open(ECHOLISTFH, "<echo5020.lst"))
 {
  while(<ECHOLISTFH>)
  {
   chomp;
 
   next if /^\;/o;
  
   if (/^[^,]*\,([^,]+)\,([^,]+)\,/o)
   {
    $echotag = uc($1);
    $descr = $2;
  
    $areas{$echotag} = GetMaxDescr($descr, $areas{$echotag});
   }
  }
  close(ECHOLISTFH);
 }
}

1;
 