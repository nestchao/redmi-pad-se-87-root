@echo off
chcp 65001 >nul 2>&1
setlocal EnableExtensions EnableDelayedExpansion

rem ===========================================================================
rem  Redmi Pad SE 8.7 - temporary root (CVE-2026-98260)
rem
rem  Windows opens a .ps1 file in Notepad when you double-click it, which is
rem  why the PowerShell script looks like it "does nothing". This .bat is the
rem  thing to run: double-click it, or call it from cmd.
rem
rem    temp-root.bat                 normal run
rem    temp-root.bat -ProbeOnly      self-test only, does NOT trigger the UAF
rem    temp-root.bat -RebootRetry    reboot first if a previous run is stuck
rem    temp-root.bat -MaxAttempts 8  more retries when it fails
rem    temp-root.bat -Force          run even if already rooted
rem ===========================================================================

set "HERE=%~dp0"
set "PS1=%HERE%temp-root.ps1"

rem Was -ProbeOnly passed? It changes what the closing message should say.
set "PROBEONLY="
echo %* | findstr /i /c:"-probeonly" >nul 2>&1 && set "PROBEONLY=1"

if not exist "%PS1%" (
    echo.
    echo   [X] temp-root.ps1 not found next to this file:
    echo       %PS1%
    echo.
    echo   Keep the .bat and the .ps1 in the same folder.
    echo.
    pause
    exit /b 2
)

rem Prefer PowerShell 7, fall back to Windows PowerShell 5.1.
set "PSEXE="
where pwsh.exe >nul 2>&1 && set "PSEXE=pwsh.exe"
if not defined PSEXE (
    where powershell.exe >nul 2>&1 && set "PSEXE=powershell.exe"
)
if not defined PSEXE (
    echo.
    echo   [X] Neither pwsh nor powershell was found on PATH.
    echo.
    pause
    exit /b 2
)

set "EXTRA="
set "RETRIED="

:run
"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %* %EXTRA%
set "RC=%ERRORLEVEL%"

rem Exit code 3 means the tablet still holds a fake cred page from an earlier
rem run and only a reboot releases it. Offer to do that and retry, once.
if "%RC%"=="3" if not defined RETRIED (
    echo.
    echo   ------------------------------------------------------------
    echo    The tablet still holds pages from an earlier run, and only a
    echo    reboot releases them. Running again without one would put two
    echo    instances over the same memory.
    echo   ------------------------------------------------------------
    set "ANS="
    set /p "ANS=  Reboot the tablet and retry automatically? [Y/N] "
    if /i not "!ANS!"=="Y" goto :report
    set "RETRIED=1"
    set "EXTRA=-RebootRetry"
    goto :run
)

:report
echo.
if "%RC%"=="0" (
    if defined PROBEONLY (
        echo   ============================================================
        echo    Self-test passed. Nothing was triggered and the tablet is
        echo    untouched. Run this .bat without -ProbeOnly to actually root.
        echo   ============================================================
    ) else (
        echo   ============================================================
        echo    Root is active. It lasts until you reboot the tablet.
        echo    To give it back:   adb reboot
        echo   ============================================================
    )
) else (
    echo   ------------------------------------------------------------
    echo    Finished with exit code %RC%.
    echo      1  = failed  ^(read the guidance above^)
    echo      2  = precondition failed  ^(kernel mismatch, no device, ...^)
    echo      3  = a previous run is stuck; another run needs a reboot
    echo   ------------------------------------------------------------
)
echo.
pause
exit /b %RC%
