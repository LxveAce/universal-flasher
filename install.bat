@echo off
REM Install Headless Marauder on Windows
REM Run from inside the git clone:  install.bat
setlocal enabledelayedexpansion

set "APP=headless-marauder"
set "NAME=Headless Marauder"
set "HERE=%~dp0"
set "HERE=%HERE:~0,-1%"
set "BINDIR=%USERPROFILE%\.local\bin"

echo [*] Installing %NAME% from: %HERE%

REM 1. Check Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python not found. Install Python 3.9+ from https://python.org
    echo     Make sure "Add Python to PATH" is checked during install.
    pause
    exit /b 1
)

REM 2. Create venv
if not exist "%HERE%\.venv" (
    echo [*] Creating virtual environment...
    python -m venv "%HERE%\.venv"
)

echo [*] Installing dependencies...
"%HERE%\.venv\Scripts\pip.exe" install -q --upgrade pip
"%HERE%\.venv\Scripts\pip.exe" install -q -r "%HERE%\requirements.txt"

REM 3. Install PyQt5 into venv
echo [*] Installing PyQt5...
"%HERE%\.venv\Scripts\pip.exe" install -q PyQt5 2>nul
if errorlevel 1 (
    echo [!] PyQt5 install failed — Qt GUI won't run, but TUI and Tkinter still will.
)

REM 4. Create global launcher scripts
echo [*] Creating launchers in %BINDIR%...
if not exist "%BINDIR%" mkdir "%BINDIR%"

(
echo @echo off
echo cd /d "%HERE%"
echo "%HERE%\.venv\Scripts\python.exe" "%HERE%\gui_qt\app.py" %%*
) > "%BINDIR%\%APP%.bat"

(
echo @echo off
echo cd /d "%HERE%"
echo "%HERE%\.venv\Scripts\python.exe" "%HERE%\gui\app.py" %%*
) > "%BINDIR%\%APP%-tk.bat"

(
echo @echo off
echo cd /d "%HERE%"
echo "%HERE%\.venv\Scripts\python.exe" "%HERE%\tui\app.py" %%*
) > "%BINDIR%\%APP%-tui.bat"

(
echo @echo off
echo cd /d "%HERE%"
echo "%HERE%\.venv\Scripts\python.exe" "%HERE%\web\app.py" %%*
) > "%BINDIR%\%APP%-web.bat"

REM 5. Add to user PATH if not already there
echo %PATH% | findstr /i /c:"%BINDIR%" >nul 2>&1
if errorlevel 1 (
    echo [*] Adding %BINDIR% to your user PATH...
    powershell -NoProfile -Command ^
      "$old = [Environment]::GetEnvironmentVariable('PATH','User'); ^
       if ($old -notlike '*%BINDIR%*') { ^
         [Environment]::SetEnvironmentVariable('PATH', '%BINDIR%;' + $old, 'User') ^
       }"
    echo [+] PATH updated. Open a NEW terminal for it to take effect.
)

REM 6. Create Start Menu shortcut
powershell -NoProfile -Command ^
  "$ws = New-Object -ComObject WScript.Shell; ^
   $startMenu = [Environment]::GetFolderPath('StartMenu'); ^
   $sc = $ws.CreateShortcut(\"$startMenu\Programs\Headless Marauder.lnk\"); ^
   $sc.TargetPath = '%BINDIR%\%APP%.bat'; ^
   $sc.WorkingDirectory = '%HERE%'; ^
   $sc.Description = 'Control and flash a headless ESP32 Marauder'; ^
   $sc.Save()" 2>nul

if not errorlevel 1 (
    echo [+] Start Menu shortcut created.
) else (
    echo [!] Could not create Start Menu shortcut.
)

echo.
echo ============================================================
echo  [+] Installed %NAME% v1.2.0
echo ============================================================
echo.
echo  Run from anywhere (open a NEW terminal first):
echo.
echo    headless-marauder          PyQt5 GUI (recommended)
echo    headless-marauder-tk       Tkinter GUI (lightweight)
echo    headless-marauder-tui      Terminal UI (SSH-friendly)
echo    headless-marauder-web      Browser UI (localhost:5000)
echo.
echo  Update:
echo    cd %HERE%
echo    git pull
echo    .venv\Scripts\pip.exe install -q -r requirements.txt
echo.
echo  Or use in-app: Help ^> Check for Updates
echo.
echo  NOTE: Install the CH340 driver if Windows doesn't detect
echo  your ESP32: https://www.wch-ic.com/downloads/CH341SER_EXE.html
echo.
pause
