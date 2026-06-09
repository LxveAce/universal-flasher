@echo off
REM Uninstall Headless Marauder launcher scripts, PATH entry, and Start Menu shortcut.
REM The project folder and .venv are left in place — delete them manually.
setlocal

set "APP=headless-marauder"
set "BINDIR=%USERPROFILE%\.local\bin"

echo [*] Removing launchers from %BINDIR%...
del /q "%BINDIR%\%APP%.bat" 2>nul
del /q "%BINDIR%\%APP%-tk.bat" 2>nul
del /q "%BINDIR%\%APP%-tui.bat" 2>nul
del /q "%BINDIR%\%APP%-web.bat" 2>nul

echo [*] Removing Start Menu shortcut...
powershell -NoProfile -Command ^
  "$startMenu = [Environment]::GetFolderPath('StartMenu'); ^
   Remove-Item \"$startMenu\Programs\Headless Marauder.lnk\" -ErrorAction SilentlyContinue" 2>nul

echo.
echo [+] Removed launchers + Start Menu shortcut.
echo     The project folder and its .venv are untouched — delete them manually to fully remove.
echo     To remove %BINDIR% from PATH, edit Environment Variables in System Settings.
pause
