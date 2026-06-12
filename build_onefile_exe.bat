@echo off
setlocal EnableExtensions
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher py.exe not found. Install Python 3 from python.org and enable "Add Python to PATH".
  pause
  exit /b 1
)
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)" >nul 2>nul
if errorlevel 1 (
  echo Python 3.8 or newer is required to build TelemtDeployer.exe.
  pause
  exit /b 1
)
if not exist .venv-build (
  py -3 -m venv .venv-build
  if errorlevel 1 pause & exit /b 1
)
call .venv-build\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements-build.txt
pyinstaller --onefile --windowed --clean --name TelemtDeployer telemt_gui_deployer.py
if errorlevel 1 (
  echo Build failed.
  pause
  exit /b 1
)
copy /Y dist\TelemtDeployer.exe .\TelemtDeployer.exe >nul
if exist build rmdir /S /Q build
if exist TelemtDeployer.spec del /Q TelemtDeployer.spec

echo.
echo Done: %cd%\TelemtDeployer.exe
echo This is a single-file Windows EXE. You can copy only TelemtDeployer.exe to another Windows PC.
echo.
set /p CLEAN="Delete everything except TelemtDeployer.exe? [y/N]: "
if /I "%CLEAN%"=="Y" goto cleanup
if /I "%CLEAN%"=="YES" goto cleanup

echo Keeping build/source files.
pause
exit /b 0

:cleanup
echo Cleaning build/source files...
if exist .venv-build rmdir /S /Q .venv-build
if exist dist rmdir /S /Q dist
if exist build rmdir /S /Q build
if exist __pycache__ rmdir /S /Q __pycache__
if exist requirements-build.txt del /Q requirements-build.txt
if exist telemt_gui_deployer.py del /Q telemt_gui_deployer.py
if exist TelemtDeployer.spec del /Q TelemtDeployer.spec

echo.
echo Cleanup complete. Only TelemtDeployer.exe should remain.
echo This window will close after you press any key.
pause >nul
start "" cmd /c "timeout /t 1 /nobreak >nul & del /Q "%~f0""
exit /b 0
