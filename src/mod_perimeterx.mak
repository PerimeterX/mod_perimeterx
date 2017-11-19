!IF "$(HTTPD)" == ""
HTTPD=c:\httpd-2.4.29
EXT_LIBS=c:\ext_libs
!MESSAGE No httpd location specified. Defaulting to $(HTTPD)
!ENDIF 

!IF "$(CFG)" == ""
CFG=mod_perimeterx - Win32 Release
!MESSAGE No configuration specified. Defaulting to mod_perimeterx - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "mod_perimeterx - Win32 Release" && "$(CFG)" != "mod_perimeterx - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_perimeterx.mak" CFG="mod_perimeterx - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_perimeterx - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_perimeterx - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "mod_perimeterx - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

ALL : "$(OUTDIR)\mod_perimeterx.so" "$(DS_POSTBUILD_DEP)"

CLEAN :
	-@erase "$(INTDIR)\mod_perimeterx.obj"
	-@erase "$(INTDIR)\curl_pool.obj"
	-@erase "$(INTDIR)\mustach.obj"
	-@erase "$(INTDIR)\px_client.obj"
	-@erase "$(INTDIR)\px_enforcer.obj"
	-@erase "$(INTDIR)\px_json.obj"
	-@erase "$(INTDIR)\px_payload.obj"
	-@erase "$(INTDIR)\px_template.obj"
	-@erase "$(INTDIR)\px_utils.obj"
	-@erase "$(INTDIR)\mod_perimeterx.res"
	-@erase "$(INTDIR)\mod_perimeterx_src.idb"
	-@erase "$(INTDIR)\mod_perimeterx_src.pdb"
	-@erase "$(OUTDIR)\mod_perimeterx.exp"
	-@erase "$(OUTDIR)\mod_perimeterx.lib"
	-@erase "$(OUTDIR)\mod_perimeterx.pdb"
	-@erase "$(OUTDIR)\mod_perimeterx.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /Oy- /I "$(HTTPD)/include" /I "$(HTTPD)/srclib/apr/include" /I "$(HTTPD)/srclib/apr-util/include" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_perimeterx_src" /FD /c /I "C:\Users\johnnyt\Downloads\jansson-2.10\build\include" /I "C:\Users\johnnyt\Downloads\curl-7.56.1\include" /I "C:\Users\johnnyt\Downloads\openssl-1.0.2m.tar\openssl-1.0.2m\openssl-1.0.2m\include" /I "C:\ext_libs"

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
RSC=rc.exe
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\mod_perimeterx.res" /i "$(HTTPD)/include" /i "$(HTTPD)/srclib/apr/include" /d "NDEBUG" /d BIN_NAME="mod_perimeterx.so" /d LONG_NAME="perimeterx_module for Apache" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_perimeterx.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_perimeterx.pdb" /debug /out:"$(OUTDIR)\mod_perimeterx.so" /implib:"$(OUTDIR)\mod_perimeterx.lib" /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\mod_perimeterx.obj" \
	"$(INTDIR)\curl_pool.obj" \
	"$(INTDIR)\mustach.obj" \
	"$(INTDIR)\px_client.obj" \
	"$(INTDIR)\px_enforcer.obj" \
	"$(INTDIR)\px_json.obj" \
	"$(INTDIR)\px_payload.obj" \
	"$(INTDIR)\px_template.obj" \
	"$(INTDIR)\px_utils.obj" \
	"$(HTTPD)\srclib\apr\Release\libapr-1.lib" \
	"$(HTTPD)\srclib\apr-util\Release\libaprutil-1.lib" \
	"$(HTTPD)\Release\libhttpd.lib" \
	"$(EXT_LIBS)\libcurl.lib" \
	"$(EXT_LIBS)\jansson.lib" 


"$(OUTDIR)\mod_perimeterx.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Release\mod_perimeterx.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\mod_perimeterx.so"
   if exist .\Release\mod_perimeterx.so.manifest mt.exe -manifest .\Release\mod_perimeterx.so.manifest -outputresource:.\Release\mod_perimeterx.so;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ELSEIF  "$(CFG)" == "mod_perimeterx - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

ALL : "$(OUTDIR)\mod_perimeterx.so" "$(DS_POSTBUILD_DEP)"

CLEAN :
	-@erase "$(INTDIR)\mod_perimeterx.obj"
	-@erase "$(INTDIR)\curl_pool.obj"
	-@erase "$(INTDIR)\fcu.obj"
	-@erase "$(INTDIR)\px_client.obj"
	-@erase "$(INTDIR)\px_enforcer.obj"
	-@erase "$(INTDIR)\px_json.obj"
	-@erase "$(INTDIR)\px_payload.obj"
	-@erase "$(INTDIR)\px_template.obj"
	-@erase "$(INTDIR)\px_utils.obj"
	-@erase "$(INTDIR)\mod_perimeterx.res"
	-@erase "$(INTDIR)\mod_perimeterx_src.idb"
	-@erase "$(INTDIR)\mod_perimeterx_src.pdb"
	-@erase "$(OUTDIR)\mod_perimeterx.exp"
	-@erase "$(OUTDIR)\mod_perimeterx.lib"
	-@erase "$(OUTDIR)\mod_perimeterx.pdb"
	-@erase "$(OUTDIR)\mod_perimeterx.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Zi /Od /I "$(HTTPD)/include" /I "$(HTTPD)/srclib/apr/include" /I "$(HTTPD)/srclib/apr-util/include" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_perimeterx_src" /FD /EHsc /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::r
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
RSC=rc.exe
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\mod_perimeterx.res" /i "$(HTTPD)/include" /i "$(HTTPD)/srclib/apr/include" /d "_DEBUG" /d BIN_NAME="mod_perimeterx.so" /d LONG_NAME="perimeterx_module for Apache" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_perimeterx.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_perimeterx.pdb" /debug /out:"$(OUTDIR)\mod_perimeterx.so" /implib:"$(OUTDIR)\mod_perimeterx.lib" /base:@$(HTTPD)\os\win32\BaseAddr.ref,mod_perimeterx.so 
LINK32_OBJS= \
	"$(INTDIR)\mod_perimeterx.obj" \
	"$(INTDIR)\mod_perimeterx.res" \
	"$(HTTPD)\srclib\apr\Debug\libapr-1.lib" \
	"$(HTTPD)\srclib\apr-util\Debug\libaprutil-1.lib" \
	"$(HTTPD)\Debug\libhttpd.lib"

"$(OUTDIR)\mod_perimeterx.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Debug\mod_perimeterx.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\mod_perimeterx.so"
   if exist .\Debug\mod_perimeterx.so.manifest mt.exe -manifest .\Debug\mod_perimeterx.so.manifest -outputresource:.\Debug\mod_perimeterx.so;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("mod_perimeterx.dep")
!INCLUDE "mod_perimeterx.dep"
!ELSE 
!MESSAGE Warning: cannot find "mod_perimeterx.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "mod_perimeterx - Win32 Release" || "$(CFG)" == "mod_perimeterx - Win32 Debug"

SOURCE=$(HTTPD)\build\win32\httpd.rc

!IF  "$(CFG)" == "mod_perimeterx - Win32 Release"


"$(INTDIR)\mod_perimeterx.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\mod_perimeterx.res" /i "$(HTTPD)/include" /i "$(HTTPD)/srclib/apr/include" /i "$(HTTPD)\build\win32" /d "NDEBUG" /d BIN_NAME="mod_perimeterx.so" /d LONG_NAME="perimeterx_module for Apache" $(SOURCE)


!ELSEIF  "$(CFG)" == "mod_perimeterx - Win32 Debug"


"$(INTDIR)\mod_perimeterx.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\mod_perimeterx.res" /i "$(HTTPD)/include" /i "$(HTTPD)/srclib/apr/include" /i "$(HTTPD)\build\win32" /d "_DEBUG" /d BIN_NAME="mod_perimeterx.so" /d LONG_NAME="perimeterx_module for Apache" $(SOURCE)


!ENDIF 

SOURCE=.\mod_perimeterx.c

"$(INTDIR)\mod_perimeterx.obj" : $(SOURCE) "$(INTDIR)"

SOURCE=.\curl_pool.c

"$(INTDIR)\curl_pool.obj": $(SOURCE) "$(INTDIR)"

SOURCE=.\mustach.c

"$(INTDIR)\mustach.obj": $(SOURCE) "$(INTDIR)"

SOURCE=.\px_client.c

"$(INTDIR)\px_client.obj": $(SOURCE) "$(INTDIR)"

SOURCE=.\px_enforcer.c

"$(INTDIR)\px_enforcer.obj": $(SOURCE) "$(INTDIR)"

SOURCE=.\px_json.c

"$(INTDIR)\px_json.obj": $(SOURCE) "$(INTDIR)"

SOURCE=.\px_payload.c

"$(INTDIR)\px_payload.obj": $(SOURCE) "$(INTDIR)"

SOURCE=.\px_template.c

"$(INTDIR)\px_template.obj": $(SOURCE) "$(INTDIR)"

SOURCE=.\px_utils.c

"$(INTDIR)\px_utils.obj": $(SOURCE) "$(INTDIR)"

!ENDIF 

