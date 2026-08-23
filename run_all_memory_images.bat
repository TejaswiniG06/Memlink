@echo off
setlocal EnableExtensions

rem ============================================================
rem CFReDS Team B - Volatility Memory Extraction
rem ============================================================

set "PROJECT=D:\cfreds team b"
set "PY=py"
set "VOL=%PROJECT%\volatility3\vol.py"
set "DATA=%PROJECT%\memory-images"
set "OUTPUT=%PROJECT%\outputs"

echo ============================================================
echo CFReDS Memory Image Extraction
echo ============================================================

rem ============================================================
rem Pre-run validation
rem ============================================================

%PY% --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python launcher 'py' is not available.
    pause
    exit /b 1
)

if not exist "%VOL%" (
    echo ERROR: Volatility was not found:
    echo %VOL%
    pause
    exit /b 1
)

if not exist "%DATA%" (
    echo ERROR: Memory-images folder was not found:
    echo %DATA%
    pause
    exit /b 1
)

if not exist "%OUTPUT%" mkdir "%OUTPUT%"

echo Python found.
echo Volatility found.
echo Memory-images folder found.
echo.

rem ============================================================
rem Process all five memory images
rem Existing non-empty outputs will be skipped automatically.
rem ============================================================

call :ANALYSE "boomer-win2k-2006-02-27-0824.img" "boomer-win2k"
call :ANALYSE "boomer-win2003-2006-03-17.img" "boomer-win2003"
call :ANALYSE "vista-beta2.img" "vista-beta2"
call :ANALYSE "xp-laptop-2005-06-25.img" "xp-laptop-2005-06-25"
call :ANALYSE "xp-laptop-2005-07-04-1430.img" "xp-laptop-2005-07-04"

echo.
echo ============================================================
echo All available memory images have been processed.
echo Check each case folder and its logs folder.
echo ============================================================
pause
exit /b 0


rem ============================================================
rem Analyse one memory image
rem ============================================================

:ANALYSE

set "IMAGE=%DATA%\%~1"
set "CASE=%OUTPUT%\%~2"
set "LOGS=%CASE%\logs"

echo.
echo ============================================================
echo Processing image: %~1
echo Case folder: %CASE%
echo ============================================================

if not exist "%IMAGE%" (
    echo [IMAGE MISSING] %IMAGE%
    exit /b 0
)

if not exist "%CASE%" mkdir "%CASE%"
if not exist "%LOGS%" mkdir "%LOGS%"

call :RUNTEXT "windows.info" "info"

call :RUNCSV "windows.pslist" "pslist"
call :RUNCSV "windows.psscan" "psscan"
call :RUNCSV "windows.pstree" "pstree"
call :RUNCSV "windows.cmdline" "cmdline"
call :RUNCSV "windows.dlllist" "dlllist"
call :RUNCSV "windows.handles" "handles"
call :RUNCSV "windows.filescan" "filescan"
call :RUNCSV "windows.malfind" "malfind"

call :RUNCSV "windows.ldrmodules" "ldrmodules"
call :RUNCSV "windows.modules" "modules"
call :RUNCSV "windows.modscan" "modscan"
call :RUNCSV "windows.netscan" "netscan"
call :RUNCSV "windows.vadinfo" "vadinfo"

echo Completed image: %~1
exit /b 0


rem ============================================================
rem Run a CSV-output plugin
rem ============================================================

:RUNCSV

set "PLUGIN=%~1"
set "NAME=%~2"
set "TEMPFILE=%CASE%\%NAME%_temporary.csv"
set "FINALFILE=%CASE%\%NAME%.csv"
set "ERRORFILE=%LOGS%\%NAME%_error.txt"

rem Skip an existing non-empty output
if exist "%FINALFILE%" (
    for %%S in ("%FINALFILE%") do (
        if %%~zS GTR 0 (
            echo [SKIPPED - ALREADY EXISTS] %PLUGIN%
            exit /b 0
        )
    )
)

echo Running %PLUGIN%...

%PY% "%VOL%" -f "%IMAGE%" -r csv %PLUGIN% ^
    > "%TEMPFILE%" 2> "%ERRORFILE%"

if errorlevel 1 (
    echo [FAILED] %PLUGIN%
    if exist "%TEMPFILE%" del "%TEMPFILE%"
    exit /b 0
)

if not exist "%TEMPFILE%" (
    echo [NO OUTPUT] %PLUGIN%
    exit /b 0
)

for %%S in ("%TEMPFILE%") do (
    if %%~zS GTR 0 (
        move /Y "%TEMPFILE%" "%FINALFILE%" >nul
        echo [SUCCESS] %PLUGIN%
    ) else (
        echo [EMPTY] %PLUGIN%
        del "%TEMPFILE%"
    )
)

exit /b 0


rem ============================================================
rem Run a text-output plugin
rem ============================================================

:RUNTEXT

set "PLUGIN=%~1"
set "NAME=%~2"
set "TEMPFILE=%CASE%\%NAME%_temporary.txt"
set "FINALFILE=%CASE%\%NAME%.txt"
set "ERRORFILE=%LOGS%\%NAME%_error.txt"

rem Skip an existing non-empty output
if exist "%FINALFILE%" (
    for %%S in ("%FINALFILE%") do (
        if %%~zS GTR 0 (
            echo [SKIPPED - ALREADY EXISTS] %PLUGIN%
            exit /b 0
        )
    )
)

echo Running %PLUGIN%...

%PY% "%VOL%" -f "%IMAGE%" %PLUGIN% ^
    > "%TEMPFILE%" 2> "%ERRORFILE%"

if errorlevel 1 (
    echo [FAILED] %PLUGIN%
    if exist "%TEMPFILE%" del "%TEMPFILE%"
    exit /b 0
)

if not exist "%TEMPFILE%" (
    echo [NO OUTPUT] %PLUGIN%
    exit /b 0
)

for %%S in ("%TEMPFILE%") do (
    if %%~zS GTR 0 (
        move /Y "%TEMPFILE%" "%FINALFILE%" >nul
        echo [SUCCESS] %PLUGIN%
    ) else (
        echo [EMPTY] %PLUGIN%
        del "%TEMPFILE%"
    )
)

exit /b 0