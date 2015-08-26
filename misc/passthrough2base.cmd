@echo off
setlocal enableextensions enabledelayedexpansion
rem Данный скрипт переводит из passthrough в базу все эхи в конфиге HPT.
rem Все настолько просто и прозрачно, что даже комментировать лень.
rem С вопросами обращаться к автору Stas Mishchenkov 2:460/58.0
rem Распространяется As Is, свободно и бесплатно. Код открыт, правьте на здоровье.
rem Цитировать в своих скрипта можно, желательно с указанием источника. ;)

set areascfg=D:\Fido\hpt\areas.cfg
set areascfgOUT=D:\Fido\hpt\areas.out
set msgbasedir=D:\Fido\mail\echo

echo # > %areascfgOUT%
echo # areas.cfg converted by %~nx0, %date% %time:~0,-6%.>> %areascfgOUT%
echo # >> %areascfgOUT%
rem                  a b c d e f
FOR /F "eol=# tokens=1,2,3,4,5* delims= " %%a in (%areascfg%) do if /i not %%c==passthrough (
     echo %%a %%b %%c %%d %%e %%f >>%areascfgOUT% ) else (
     echo %%a %%b %msgbasedir%\%%b -b Squish -p 0 -dupeCheck move %%d %%e %%f>>%areascfgOUT%
     )
copy %areascfg% %areascfg%.%date%.%random%
copy %areascfgOUT% %areascfg%
