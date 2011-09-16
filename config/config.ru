# main fidoconfig file
#
name Dummy point station
sysop Ivan Durak
location Moscow, Russia
address 2:5020/9999.99
# каталоги
# входящий для непарольных сессий
inbound /home/username/fido/inbound/insecure
# аналогично - для парольных сессий
protinbound /home/username/fido/inbound
# исходящие файлы
outbound /home/username/fido/outbound
# временные каталоги для тоссинга и паковки
tempinbound /home/username/fido/tmp.inbound
tempoutbound /home/username/fido/tmp.outbound
# лог; если что-то не работает - читать здесь
logfiledir /home/username/fido/log
# дупобаза
dupehistorydir /home/username/fido/dupebase
# нодлист искать здесь
nodelistdir /home/username/fido/etc
# база сообщений
msgbasedir /home/username/fido/msgbase
# результаты работы тоссера, могут использоваться другими программами
echotosslog /home/username/fido/log/toss.log
importlog /home/username/fido/log/import.log

# строить цепочки ответов только для новых сообщений
linkwithimportlog kill
# отдельные каталоги для линков
separatebundles yes
# не светить версии ПО
disablepid yes
disabletid yes
# Perl-обработчики; подробное описание - в файле perlhooks
#hptperlfile /home/username/fido/lib/hptfunctions.pl
# настройки архиваторов; дополнительные примеры - в файле packers
pack zip zip -9 -j -q $a $f
unpack "unzip -j -Loqq $a $f -d $p" 0 504b0304

# сюда будут складываться сообщения нам в конференциях
carbonto Ivan Durak
carboncopy PERSONAL.MAIL

# сообщения для роботов будут приниматься и отправляться здесь
robotsarea NETMAIL

# настройки, общие для всех роботов
robot default
# удалять сообщения с запросами
killrequests yes
# атрибуты для сообщений с ответами
reportsattr loc pvt k/s npd

# настройки только для этого робота
robot areafix
fromname Areafix robot
robotorigin Areafix robot

# настройки, общие для всех линков; остальное - в файле links
linkdefaults begin
# если пакет получен по защищенной сессии - в нем может не быть пароля
allowemptypktpwd secure
# архиватор по умолчанию; для отдельных линков можно указывать другой
packer zip
# автоматическое создание конференций;
# рекомендуется оставить здесь off, а для отдельных линков включать явно
areafixautocreate off
# параметры автосоздания
areafixautocreatedefaults -b squish -dupecheck del -dupehistory 14
# файл с описаниями конференций
areafixautocreatefile /home/username/fido/etc/areas
# по умолчанию отправляем пакеты сами, не дожидаясь входящих соединений
echomailflavour direct
# запретить пересылку запросов к роботам
forwardrequests off
linkdefaults end

# описание линков
include /home/username/fido/etc/links
# и маршрутизации нетмейла
include /home/username/fido/etc/route

# описания конференций
# основная нетмейловая конференция - должна присутствовать обязательно
netmailarea NETMAIL       /home/username/fido/msgbase/netmail       -b squish
# сюда падают сообщения, которые тоссер не сумел обработать
badarea     BAD           /home/username/fido/msgbase/bad           -b squish
# сюда падают дупы при использовании dupecheck move
dupearea    DUPE          /home/username/fido/msgbase/dupe          -b squish
# сюда откладываются копии сообщений, адресованных нам
localarea   PERSONAL.MAIL /home/username/fido/msgbase/personal.mail -b squish

# эхоконференции
include /home/username/fido/etc/areas
