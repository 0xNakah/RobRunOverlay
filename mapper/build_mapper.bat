@echo off
setlocal enabledelayedexpansion
rem Build the custom EAC-hardened kernel driver mapper.
rem Output: mapper.exe in this folder.
rem Requires Visual Studio with C++ toolset and Windows SDK.
cd /d "%~dp0"

set "VS="
for %%P in (
    "C:\Program Files\Microsoft Visual Studio\2022\Community"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional"
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
    "C:\Program Files\Microsoft Visual Studio\2022\BuildTools"
    "C:\Program Files\Microsoft Visual Studio\17\Community"
    "C:\Program Files\Microsoft Visual Studio\17\Professional"
    "C:\Program Files\Microsoft Visual Studio\17\Enterprise"
) do (
    if not defined VS if exist "%%~P\VC\Auxiliary\Build\vcvars64.bat" set "VS=%%~P"
)
if not defined VS (
    echo [ERROR] Visual Studio with the C++ toolset not found.
    pause
    exit /b 1
)

call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo [ERROR] vcvars64.bat failed.
    pause
    exit /b 1
)

set "CFLAGS=/nologo /O2 /W3 /MT /std:c++17 /D_CRT_SECURE_NO_WARNINGS /EHsc"
set "LIBS=advapi32.lib kernel32.lib user32.lib"

echo [1/2] compiling main.cpp
cl %CFLAGS% /c main.cpp /Fo:main.obj || goto fail
echo [2/2] compiling physical_memory.cpp
cl %CFLAGS% /c physical_memory.cpp /Fo:physical_memory.obj || goto fail

echo [3/3] linking mapper.exe
cl %CFLAGS% main.obj physical_memory.obj /Fe:mapper.exe /link /SUBSYSTEM:CONSOLE %LIBS% || goto fail

del /q main.obj physical_memory.obj 2>nul
echo.
echo BUILD_OK  -  mapper.exe
echo.
echo Usage: mapper.exe driver.sys [ntoskrnl_base_hex]
echo Example: mapper.exe ..\driver\driver.sys 0xFFFFF80000000000
echo.
echo NOTE: Run as administrator (requires SeDebugPrivilege for \\.\PhysicalMemory)
exit /b 0

:fail
echo BUILD_FAIL
exit /b 1