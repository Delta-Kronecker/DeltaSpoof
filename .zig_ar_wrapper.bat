@echo off
setlocal enabledelayedexpansion
set "ZIG=C:\\msys64\\clang64\\bin\\zig.exe"
set "ARGS=%*"
"%ZIG%" ar %ARGS%
if %ERRORLEVEL% equ 0 exit /b 0
set "ARCHIVE="
set "FILES="
set "MODE=parse"
for %%a in (%ARGS%) do (
    if "!MODE!"=="parse" (
        set "arg=%%~a"
        if "!arg:~0,1!"=="-" (
            rem skip options
        ) else if "!arg!"=="cq" (
            set "MODE=archive"
        ) else if "!arg!"=="cr" (
            set "MODE=archive"
        ) else if "!arg!"=="rcs" (
            set "MODE=archive"
        ) else if "!arg!"=="q" (
            set "MODE=archive"
        ) else if "!arg!"=="r" (
            set "MODE=archive"
        ) else (
            set "MODE=files"
            set "ARCHIVE=%%~a"
        )
    ) else if "!MODE!"=="archive" (
        set "ARCHIVE=%%~a"
        set "MODE=files"
    ) else if "!MODE!"=="files" (
        if not defined FILES (
            set "FILES=%%~a"
        ) else (
            set "FILES=!FILES! %%~a"
        )
    )
)
if not defined ARCHIVE exit /b 1
set "MRI=%TEMP%\ar_mri_%RANDOM%.txt"
echo create %ARCHIVE%>"%MRI%"
if defined FILES (
    for %%f in (!FILES!) do (
        echo addmod %%f>>"%MRI%"
    )
)
echo save>>"%MRI%"
echo end>>"%MRI%"
"%ZIG%" ar -M < "%MRI%"
set "EC=!ERRORLEVEL!"
del "%MRI%" 2>nul
exit /b !EC!
