# Microsoft Developer Studio Project File - Name="hpt" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=hpt - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "hpt.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "hpt.mak" CFG="hpt - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "hpt - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "hpt - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "hpt - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\nd_r\bin"
# PROP Intermediate_Dir "..\nd_r\obj\hpt"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /Ob2 /I ".." /I ".\h" /I "D:\compilation\perl\lib\CORE" /D "NDEBUG" /D "_MBCS" /D "NO_STRICT" /D "HAVE_DES_FCRYPT" /D "PERL_IMPLICIT_CONTEXT" /D "PERL_IMPLICIT_SYS" /D "_MAKE_DLL" /D "__NT__" /D "WINNT" /D "WIN32" /D "_CONSOLE" /FR /FD /c
# SUBTRACT CPP /YX /Yc /Yu
# ADD BASE RSC /l 0x419 /d "NDEBUG"
# ADD RSC /l 0x419 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 fconfmvc.lib smapimvc.lib Kernel32.lib user32.lib delayimp.lib perl56.lib OLDNAMES.lib msvcrt.lib /nologo /subsystem:console /pdb:"..\nd_r\obj\hpt/hpt.pdb" /machine:I386 /nodefaultlib /libpath:"..\nd_r\lib" /libpath:"D:\compilation\perl\lib\CORE"
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "hpt - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\nd_d\bin"
# PROP Intermediate_Dir "..\nd_d\obj\hpt"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I ".." /I ".\h" /I "D:\compilation\perl\lib\CORE" /D "DO_PERL" /D "PERL_MSVCRT_READFIX" /D "NO_STRICT" /D "HAVE_DES_FCRYPT" /D "PERL_IMPLICIT_CONTEXT" /D "PERL_IMPLICIT_SYS" /D "_MAKE_DLL" /D "__NT__" /D "WINNT" /D "WIN32" /D "_CONSOLE" /FR /FD /GZ /c
# SUBTRACT CPP /YX /Yc /Yu
# ADD BASE RSC /l 0x419 /d "_DEBUG"
# ADD RSC /l 0x419 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo /o"..\nd_d\obj\hpt/hpt.bsc"
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 msvcrtd.lib fconfmvc.lib smapimvc.lib Kernel32.lib user32.lib delayimp.lib perl56.lib OLDNAMES.lib /nologo /subsystem:console /debug /machine:I386 /nodefaultlib /libpath:"..\nd_d\lib" /libpath:"D:\compilation\perl\lib\CORE" /delayload:perl56.dll
# SUBTRACT LINK32 /verbose /profile /force

!ENDIF 

# Begin Target

# Name "hpt - Win32 Release"
# Name "hpt - Win32 Debug"
# Begin Group "Header Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\h\areafix.h
# End Source File
# Begin Source File

SOURCE=.\h\cvsdate.h
# End Source File
# Begin Source File

SOURCE=.\h\dupe.h
# End Source File
# Begin Source File

SOURCE=.\h\fcommon.h
# End Source File
# Begin Source File

SOURCE=.\h\global.h
# End Source File
# Begin Source File

SOURCE=.\h\hpt.h
# End Source File
# Begin Source File

SOURCE=.\h\hptperl.h
# End Source File
# Begin Source File

SOURCE=.\h\link.h
# End Source File
# Begin Source File

SOURCE=.\h\pkt.h
# End Source File
# Begin Source File

SOURCE=.\h\post.h
# End Source File
# Begin Source File

SOURCE=.\h\query.h
# End Source File
# Begin Source File

SOURCE=.\h\scan.h
# End Source File
# Begin Source File

SOURCE=.\h\scanarea.h
# End Source File
# Begin Source File

SOURCE=.\h\seenby.h
# End Source File
# Begin Source File

SOURCE=.\h\stat.h
# End Source File
# Begin Source File

SOURCE=.\h\toss.h
# End Source File
# Begin Source File

SOURCE=.\h\version.h
# End Source File
# End Group
# Begin Source File

SOURCE=.\src\areafix.c
# End Source File
# Begin Source File

SOURCE=.\src\carbon.c
# End Source File
# Begin Source File

SOURCE=.\src\dupe.c
# End Source File
# Begin Source File

SOURCE=.\src\fcommon.c
# End Source File
# Begin Source File

SOURCE=.\src\global.c
# End Source File
# Begin Source File

SOURCE=.\src\hpt.c
# End Source File
# Begin Source File

SOURCE=.\src\link.c
# End Source File
# Begin Source File

SOURCE=.\src\perl.c
# End Source File
# Begin Source File

SOURCE=.\src\pktread.c
# End Source File
# Begin Source File

SOURCE=.\src\pktwrite.c
# End Source File
# Begin Source File

SOURCE=.\src\post.c
# End Source File
# Begin Source File

SOURCE=.\src\query.c
# End Source File
# Begin Source File

SOURCE=.\src\scan.c
# End Source File
# Begin Source File

SOURCE=.\src\scanarea.c
# End Source File
# Begin Source File

SOURCE=.\src\seenby.c
# End Source File
# Begin Source File

SOURCE=.\src\stat.c
# End Source File
# Begin Source File

SOURCE=.\src\toss.c
# End Source File
# End Target
# End Project
