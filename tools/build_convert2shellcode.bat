@echo off
setlocal EnableExtensions

for %%I in ("%~dp0..") do set "ROOT=%%~fI"
set "BIN=%ROOT%\bin"
set "GO_ASSETS=%ROOT%\internal\rdi"
set "ASM_DIR=%ROOT%\SRDI_Asm"
set "SCRIPTS=%ROOT%\tools\scripts"
set "SRC=%ROOT%\tools\src"
set "TARGET=%ROOT%\beacon.exe"
set "OBJDIR=%TEMP%\Convert2Shellcode_%RANDOM%%RANDOM%"

if /i "%~1"=="-h" goto usage
if /i "%~1"=="--help" goto usage
if not "%~1"=="" set "TARGET=%~1"

if not exist "%BIN%" mkdir "%BIN%"
mkdir "%OBJDIR%" >nul 2>nul
if errorlevel 1 (
    echo [-] failed to create temp build directory:
    echo     %OBJDIR%
    exit /b 1
)

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" goto have_vswhere
echo [-] vswhere.exe not found:
echo     %VSWHERE%
goto fail

:have_vswhere
for /f "tokens=*" %%i in ('"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do set "VSINSTALL=%%i"
if not "%VSINSTALL%"=="" goto have_vs
echo [-] Visual Studio with VC tools not found
goto fail

:have_vs
set "VCVARSALL=%VSINSTALL%\VC\Auxiliary\Build\vcvarsall.bat"
if exist "%VCVARSALL%" goto have_vcvars
echo [-] vcvarsall.bat not found:
echo     %VCVARSALL%
goto fail

:have_vcvars
call "%VCVARSALL%" x64 >nul
if errorlevel 1 goto fail

echo [*] assembling RDI_front_v2_x64.asm
ml64 /nologo /c /Fo"%OBJDIR%\srdi_front_v2_x64.obj" "%ASM_DIR%\RDI_front_v2_x64.asm"
if errorlevel 1 goto fail
python "%SCRIPTS%\extract_rdi_text.py" "%OBJDIR%\srdi_front_v2_x64.obj" -o "%BIN%\srdi_front_v2_x64.bin"
if errorlevel 1 goto fail

echo [*] assembling RDI_post_v2_x64.asm
ml64 /nologo /c /Fo"%OBJDIR%\srdi_post_v2_x64.obj" "%ASM_DIR%\RDI_post_v2_x64.asm"
if errorlevel 1 goto fail
python "%SCRIPTS%\extract_rdi_text.py" "%OBJDIR%\srdi_post_v2_x64.obj" -o "%BIN%\srdi_post_v2_x64.bin"
if errorlevel 1 goto fail

call "%VCVARSALL%" x86 >nul
if errorlevel 1 goto fail

echo [*] assembling RDI_front_v2_x86.asm
ml /nologo /c /Fo"%OBJDIR%\srdi_front_v2_x86.obj" "%ASM_DIR%\RDI_front_v2_x86.asm"
if errorlevel 1 goto fail
python "%SCRIPTS%\extract_rdi_text.py" "%OBJDIR%\srdi_front_v2_x86.obj" -o "%BIN%\srdi_front_v2_x86.bin"
if errorlevel 1 goto fail

echo [*] assembling RDI_post_v2_x86.asm
ml /nologo /c /Fo"%OBJDIR%\srdi_post_v2_x86.obj" "%ASM_DIR%\RDI_post_v2_x86.asm"
if errorlevel 1 goto fail
python "%SCRIPTS%\extract_rdi_text.py" "%OBJDIR%\srdi_post_v2_x86.obj" -o "%BIN%\srdi_post_v2_x86.bin"
if errorlevel 1 goto fail

echo [*] compiling shellcode_loader_x86.exe
cl /nologo /W4 /O2 /Fo"%OBJDIR%\shellcode_loader_x86.obj" /Fe"%BIN%\shellcode_loader_x86.exe" "%SRC%\shellcode_loader.c"
if errorlevel 1 goto fail

call "%VCVARSALL%" x64 >nul
if errorlevel 1 goto fail

echo [*] embedding public RDI blobs into Convert2Shellcode
python "%SCRIPTS%\embed_rdi_blobs.py" ^
  --front "%BIN%\srdi_front_v2_x64.bin" ^
  --post "%BIN%\srdi_post_v2_x64.bin" ^
  --front-x86 "%BIN%\srdi_front_v2_x86.bin" ^
  --post-x86 "%BIN%\srdi_post_v2_x86.bin" ^
  -o "%BIN%\rdi_blobs.h"
if errorlevel 1 goto fail

echo [*] syncing RDI blobs into the Go module
copy /y "%BIN%\srdi_front_v2_x64.bin" "%GO_ASSETS%\srdi_front_v2_x64.bin" >nul
if errorlevel 1 goto fail
copy /y "%BIN%\srdi_post_v2_x64.bin" "%GO_ASSETS%\srdi_post_v2_x64.bin" >nul
if errorlevel 1 goto fail
copy /y "%BIN%\srdi_front_v2_x86.bin" "%GO_ASSETS%\srdi_front_v2_x86.bin" >nul
if errorlevel 1 goto fail
copy /y "%BIN%\srdi_post_v2_x86.bin" "%GO_ASSETS%\srdi_post_v2_x86.bin" >nul
if errorlevel 1 goto fail

if errorlevel 1 goto fail

echo [*] compiling Go Convert2Shellcode.exe
go build -o "%BIN%\Convert2Shellcode.exe" "%ROOT%\cmd\convert2shellcode"
if errorlevel 1 goto fail

echo [*] compiling shellcode_loader.exe
cl /nologo /W4 /O2 /Fo"%OBJDIR%\shellcode_loader.obj" /Fe"%BIN%\shellcode_loader.exe" "%SRC%\shellcode_loader.c"
if errorlevel 1 goto fail

if not exist "%TARGET%" goto skip_samples
echo [*] generating sample front shellcode
"%BIN%\Convert2Shellcode.exe" --type front --input "%TARGET%" --output "%BIN%\beacon_front_v2.bin"
if errorlevel 1 goto fail

echo [*] generating sample post shellcode
"%BIN%\Convert2Shellcode.exe" --type post --input "%TARGET%" --output "%BIN%\beacon_post_v2.bin"
if errorlevel 1 goto fail

:skip_samples
rmdir /s /q "%OBJDIR%" >nul 2>nul
echo.
echo Build complete:
echo   %BIN%\Convert2Shellcode.exe
echo   %BIN%\shellcode_loader.exe
echo   %BIN%\shellcode_loader_x86.exe
echo   %BIN%\srdi_front_v2_x64.bin
echo   %BIN%\srdi_post_v2_x64.bin
echo   %BIN%\srdi_front_v2_x86.bin
echo   %BIN%\srdi_post_v2_x86.bin
echo.
echo Usage:
echo   "%BIN%\Convert2Shellcode.exe" --arch x64 --type front --input "%TARGET%" --output "%BIN%\out_front.bin"
echo   "%BIN%\Convert2Shellcode.exe" --arch x64 --type post  --input "%TARGET%" --output "%BIN%\out_post.bin"
echo   "%BIN%\Convert2Shellcode.exe" --arch x86 --type front --input "path\to\x86.exe" --output "%BIN%\out_x86_front.bin"
echo   "%BIN%\Convert2Shellcode.exe" --arch x86 --type post  --input "path\to\x86.exe" --output "%BIN%\out_x86_post.bin"
echo.
echo Test:
echo   "%BIN%\shellcode_loader.exe" "%BIN%\beacon_front_v2.bin" 15000
echo   "%BIN%\shellcode_loader.exe" "%BIN%\beacon_post_v2.bin" 15000
exit /b 0

:fail
set "ERR=%ERRORLEVEL%"
if "%ERR%"=="0" set "ERR=1"
rmdir /s /q "%OBJDIR%" >nul 2>nul
exit /b %ERR%

:usage
echo Usage:
echo   %~nx0 [target_pe]
echo.
echo Default target:
echo   %ROOT%\beacon.exe
exit /b 0

