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
rem  The exploit is a page-reclaim race: each of its three stages lands about
rem  2 times in 3, and a failed run leaves a holder that only a reboot
rem  releases. This wrapper therefore reboots and retries on its own, up to
rem  -Cycles attempts, so that the outcome stops depending on luck.
rem
rem    temp-root.bat                 normal run, asks before rebooting
rem    temp-root.bat -RebootRetry    never ask; reboot and retry automatically
rem    temp-root.bat -ProbeOnly      self-test only, does NOT trigger the UAF
rem    temp-root.bat -Cycles 5       allow up to 5 attempts (default 3)
rem    temp-root.bat -MaxAttempts 8  more retries inside one attempt
rem    temp-root.bat -Force          run even if already rooted
rem ===========================================================================

set "HERE=%~dp0"
set "PS1=%HERE%temp-root.ps1"
set "MAXCYCLE=3"

rem Split our own -Cycles N off from the arguments forwarded to PowerShell.
set "PSARGS="
set "SKIPNEXT="
for %%A in (%*) do (
    if defined SKIPNEXT (
        set "MAXCYCLE=%%~A"
        set "SKIPNEXT="
    ) else if /i "%%~A"=="-cycles" (
        set "SKIPNEXT=1"
    ) else (
        set "PSARGS=!PSARGS! %%~A"
    )
)

set "PROBEONLY="
echo !PSARGS! | findstr /i /c:"-probeonly" >nul 2>&1 && set "PROBEONLY=1"
set "AUTO="
echo !PSARGS! | findstr /i /c:"-rebootretry" >nul 2>&1 && set "AUTO=1"

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

rem EXTRA is only ever set when we prompt, never when the user already passed
rem -RebootRetry (PowerShell rejects a switch given twice).
set "EXTRA="
set "CYCLE=0"

:run
set /a CYCLE+=1
if %CYCLE% GTR 1 (
    echo.
    echo   ================ attempt %CYCLE% of %MAXCYCLE% ================
)
"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%PS1%" !PSARGS! !EXTRA!
set "RC=%ERRORLEVEL%"

if "%RC%"=="0" goto :report
if %CYCLE% GEQ %MAXCYCLE% goto :report
if defined AUTO goto :run

rem Exit code 3 = a previous run is parked and only a reboot releases it.
if not "%RC%"=="3" goto :report

echo.
echo   ------------------------------------------------------------
echo    The tablet still holds pages from an earlier run, and only a
echo    reboot releases them. Running again without one would put two
echo    instances over the same memory.
echo   ------------------------------------------------------------
set "ANS="
set /p "ANS=  Reboot the tablet and retry automatically? [Y/N] "
if /i not "!ANS!"=="Y" goto :report
set "EXTRA=-RebootRetry"
goto :run

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
        echo    Root is active  ^(attempt %CYCLE% of %MAXCYCLE%^).
        echo    It lasts until you reboot the tablet.
        echo    To give it back:   adb reboot
        echo   ============================================================
    )
) else (
    echo   ------------------------------------------------------------
    echo    Gave up after %CYCLE% attempt^(s^), exit code %RC%.
    echo      1  = failed  ^(read the guidance above^)
    echo      2  = precondition failed  ^(kernel mismatch, no device, ...^)
    echo      3  = a previous run is stuck; another run needs a reboot
    echo    Try again with more attempts:   temp-root.bat -Cycles 5
    echo   ------------------------------------------------------------
)
echo.
pause
exit /b %RC%
