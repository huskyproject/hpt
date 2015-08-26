@echo off
setlocal enableextensions enabledelayedexpansion

rem Фронтэнд к areastat из комплекта бинарников HPT.
rem Из списка эхоарий HPT создает конфиг areastat.
rem Корректно пропускает пассру эхи, о которые спотыкается areastat. Запускает
rem сам areastat и по итогам его работы строит красивую табличку статистики
rem хождения эх за указанный период, которую и постит потом в эху, а так же список
rem эх, в кторых за указанный период не было ни одного письма.
rem
rem C вопросами обращаться к автору Stas Mishchenkov 2:460/58.0
rem Распространяется As Is, свободно и бесплатно. Код открыт, правьте на здоровье.
rem Цитировать в своих скриптах можно, но желательно с указанием источника. ;)
rem 
rem Понимает два параметра: Первый (не обязательный) - период, за который
rem делается статистика в формате конфига areastat. По умолчанию - 1 день.
rem Вторым параметром может быть флаг "dead" - в этом случае будет отправлен в эху
rem список мертвых эх.

REM Полное имя файла конфигурации HPT, в котором описаны эхоарии.
rem Крайне рекомендовано указывать полное имя файла (диск, путь, имя, раширение).
rem Подразумевается, что в нем сразу за именем файла эхообласти указан тип базы!
set areascfg=D:\Fido\hpt\areas.cfg

rem Полное имя файла, в котором делаем конфиг для areastat.
rem Крайне рекомендовано указывать полное имя файла (диск, путь, имя, раширение).
set areaSTATcfg=D:\Fido\hpt\areastat.cfg

rem Полный путь к дирректории, в которой создается статистика.
set StatDIR=d:\fido\logs\stat

rem Полное имя исполняемого файла ареастат.
set areastatexe=D:\Fido\hpt\bin\areastat.exe

rem Имя исполняемого файла HPT.
rem Крайне рекомендовано указывать полное имя файла (диск, путь имя, раширение).
set hptexe=D:\Fido\hpt\bin\hpt.exe

rem Имя файла конфигурации HPT (fidoconfig).
rem Крайне рекомендовано указывать полное имя файла (диск, путь имя, раширение).
set hptcfg=D:\Fido\hpt\hpt.cfg


rem Обязательно все в кавычках.
rem От какого имени постить...
set NameFrom="Evil Robot"
rem Куда постить статистику
set RobotEchoArea="crimea.robots"
set Subj="Статистика хождения эхоконференций"
set TEARLINE="Evil Robot"
set Origin="Lame Users Breading, Crimea."


rem Period for statistics
rem Stat_Period [m][w]<age>
rem Examples:
rem Stat_Period 60 - statistics for 60 days
rem Stat_Period w2 - statistics for 2 weeks
rem Stat_Period m1 - statistics for 1 month
if _%~1_==__ ( set statperiod=1) else ( set statperiod=%~1)

del /f/q %areaSTATcfg%
rem                  a b c d e f
FOR /F "eol=# tokens=1,2,3,4,5* delims= " %%a in (%areascfg%) do if /i not %%c==passthrough echo Area %%b %%e %%c %%b.stt>>%areaSTATcfg%
rem ;  Area <name> <type> <path> <out_file>
echo Stat_Period !statperiod!>>%areaSTATcfg%

del /f/q %StatDIR%\*
%StatDIR:~0,2%
cd %StatDIR%
%areastatexe% %areaSTATcfg%

set outfile=%StatDIR%\stat.tpl
set deadtpl=%StatDIR%\dead.tpl

set headertop=┌─────────────────────────────────────────────────────────────────────────────┐
set    header=│                     Статистика хождения эхоконференций.                     │
set   header1=├────────────────────────────────────────────────────────────┬────────┬───────┤
set   header2=│              EchoArea                                      │  Msgs  │ Users │
set   header3=├────────────────────────────────────────────────────────────┼────────┼───────┤
set    footer=└────────────────────────────────────────────────────────────┴────────┴───────┘


echo RealName: %NameFrom%>%outfile%
echo Created %DATE% %TIME:~0,-3%>>%outfile%
echo %headertop%>>%outfile%
echo %header%>>%outfile%
echo %header1%>>%outfile%
echo %header2%>>%outfile%
echo %header3%>>%outfile%
echo RealName: %NameFrom%>%deadtpl%
echo Statperiod: %statperiod%>>%deadtpl%
echo  * Dead Areas *>>%deadtpl%
echo.>>%deadtpl%

Echo Cоставляем список файлов...
set /a stem.0=0
set /a fn=1
for %%i in (%statdir%\*.stt) do set stem.!fn!=%%i&set /a stem.0=!fn!&set /a fn+=1
echo Всего найдено файлов: %stem.0%.

rem Если почему-то файлы статистики не найдены, то и делать дальше нечего.
if %stem.0%==0 exit

set /a fn=1
set /a grandtotal=0
:S1

   FOR /F "eol=; tokens=1,2,3* delims=: " %%i in (!stem.%fn%!) do if /i %%i==Area (
       set stem.!fn!.area=%%j
      ) else if /i %%i==Messages (
       set /a stem.!fn!.Messages=%%j
      ) else if /i %%i==Total (
       set /a stem.!fn!.users=%%k
      ) else if /i %%i==Period (
       set stem.!fn!.Period=%%j %%k %%l
      )

   rem затычка глюка ареастат с пустой эхой.
   if not defined stem.!fn!.area set /a fn+=1&goto S1

   set areaname=!stem.%fn%.area!                                                          ;
   set msgs=          !stem.%fn%.Messages! 
   set tusers=          !stem.%fn%.users! 
   set str=│!areaname:~0,60!│!msgs:~-8!│!tusers:~-7!│
   if !stem.%fn%.Messages! NEQ 0 (
      echo !str!
      echo !str!>>%outfile%
      echo %header3%>>%outfile%
      set /a grandtotal=!grandtotal!+!stem.%fn%.Messages!
   ) else echo !areaname:~0,40!>>%deadtpl%

   if !fn!==!stem.0! goto E1
   set /a fn+=1
   goto S1
:E1
   set msgs=          !grandtotal! 
   set FootStr=│                                                     Всего: │!msgs:~-8!│       │
   echo %FootStr%>>%outfile%
   echo %footer%>>%outfile%
   echo %FootStr%
   echo %footer%

if /i .%~2.==.dead. (
  %hptexe% -c %hptcfg% post -nf %NameFrom% -s " * Dead Areas *" -e %RobotEchoArea% -z %TEARLINE% -o %Origin% -x -f loc %deadtpl%
) else %hptexe% -c %hptcfg% post -nf %NameFrom% -s %Subj% -e %RobotEchoArea% -z %TEARLINE% -o %Origin% -x -f loc %outfile%

exit

