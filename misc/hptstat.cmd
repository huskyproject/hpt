@echo off
rem „ ­­ë© áªà¨¯â á®§¤ ¥â â ¡«¨çªã á® áâ â¨áâ¨ª®© å®¦¤¥­¨ï íå ¯® «®£ã HPT.
rem ® ¢á¥¬ ¢®¯à®á ¬ ®¡à é âìáï ª  ¢â®àã Stas Mischenkov 2:460/58.0
rem  á¯à®áâà ­ï¥âáï As Is, á¢®¡®¤­® ¨ ¡¥á¯« â­®. Š®¤ ®âªàëâ, ¯à ¢ìâ¥ ­  §¤®à®¢ì¥.
rem –¨â¨à®¢ âì ¢ á¢®¨å áªà¨¯â  ¬®¦­®, ¦¥« â¥«ì­® á ãª § ­¨¥¬ ¨áâ®ç­¨ª . ;)

setlocal enableextensions enabledelayedexpansion

rem ˆ¬ï ä ©«  «®£  HPT.
rem Šà ©­¥ à¥ª®¬¥­¤®¢ ­® ãª §ë¢ âì ¯®«­®¥ ¨¬ï ä ©«  (¤¨áª, ¯ãâì ¨¬ï, à è¨à¥­¨¥).
set hptlog=D:\fido\logs\hpt.log

rem ˆ¬ï ä ©« , ¢ ª®â®à®¬ ¡ã¤¥â á®§¤ ­  â ¡«¨çª  áâ â¨áâ¨ª¨.
rem Šà ©­¥ à¥ª®¬¥­¤®¢ ­® ãª §ë¢ âì ¯®«­®¥ ¨¬ï ä ©«  (¤¨áª, ¯ãâì ¨¬ï, à è¨à¥­¨¥).
set hptstat=D:\fido\logs\hptstat.tpl

rem ˆ¬ï ¨á¯®«­ï¥¬®£® ä ©«  HPT.
rem Šà ©­¥ à¥ª®¬¥­¤®¢ ­® ãª §ë¢ âì ¯®«­®¥ ¨¬ï ä ©«  (¤¨áª, ¯ãâì ¨¬ï, à è¨à¥­¨¥).
set hptexe=D:\Fido\hpt\bin\hpt.exe

rem ˆ¬ï ä ©«  ª®­ä¨£ãà æ¨¨ HPT (fidoconfig).
rem Šà ©­¥ à¥ª®¬¥­¤®¢ ­® ãª §ë¢ âì ¯®«­®¥ ¨¬ï ä ©«  (¤¨áª, ¯ãâì ¨¬ï, à è¨à¥­¨¥).
set hptcfg=D:\Fido\hpt\hpt.cfg

rem Ž¡ï§ â¥«ì­® ¡¥§ ª ¢ëç¥ª.
set Subj=‘â â¨áâ¨ª  å®¦¤¥­¨ï íå®ª®­ä¥à¥­æ¨©

rem Ž¡ï§ â¥«ì­® ¢á¥ ¢ ª ¢ëçª å.
set NameFrom="Evil Robot"
set RobotEchoArea="crimea.robots"
set TEARLINE="Evil Robot"
set Origin="Lame Users Breading, Crimea."


set headertop=ÚÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ¿
set    header=³                     ‘â â¨áâ¨ª  å®¦¤¥­¨ï íå®ª®­ä¥à¥­æ¨©                      ³
set   header1=ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÂÄÄÄÄÄÄÄÄ´
set   header2=³    EchoArea                                                        ³  Msgs  ³
set   header3=ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄ´
set    footer=ÀÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÁÄÄÄÄÄÄÄÄÙ

echo !headertop!>!hptstat!
echo !header!>>!hptstat!
echo !header1!>>!hptstat!
echo !header2!>>!hptstat!


set /a ww=0
set /a areaslist.0=0
rem                  a b c d e f g h i j 
FOR /F "eol=; tokens=1,2,3,4,5,6,7,8,9,* delims== " %%a in (%hptlog%) do if /i _%%d_==_area_ (
     if /i _%%c_==_echo_ (
        set t=%%e
        set t=!t:-=Ä!
        if not defined msgs.!t! (
           set /a ww=!ww!+1
           set /a msgs.!t!=%%g
           set areaslist.!ww!=!t!
        ) else (
           set /a msgs.!t!=msgs.!t!+%%g
          )
     )
    ) else if /i _%%a_==_----------_ (
            if not defined startperiod set startperiod=%%b %%c %%d %%e
            set endperiod=%%b %%c %%d %%e
           )
set /a areaslist.0=!ww!

echo * !areaslist.0! EchoAreas found.

set /a ww=1
set /a grandtotal=0
:s1

   set mm=!areaslist.%ww%!
   set areatag=!mm:Ä=-!

   set /a grandtotal=!grandtotal!+msgs.!mm!
   set areaname=³ !areatag!                                                                ;
   set msgs=             !msgs.%mm%! ³
   set str=!areaname:~0,69!³!msgs:~-9!

   echo !str!
   echo !header3!>>!hptstat!
   echo !str!>>!hptstat!

   if !ww!==%areaslist.0% goto e1
   set /a ww=!ww!+1
   goto s1
:e1
set msgs=             !grandtotal!
set str=³                             (!startperiod:,= !- !endperiod:,=) !‚á¥£®: ³!msgs:~-7! ³
echo !header3!>>!hptstat!
echo !str!>>!hptstat!
echo !footer!>>!hptstat!

%hptexe% -c %hptcfg% post -nf %NameFrom% -s "%Subj% (!startperiod:,= !- !endperiod:,=)!" -e %RobotEchoArea% -z %TEARLINE% -o %Origin% -x -f loc %hptstat%

exit
