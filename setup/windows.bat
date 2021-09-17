::
:: windows.bat
::
:: litefuzz project
::
:: setup and install deps on Windows (10 tested + Py2)
::
:: note: run as Administrator and in the litefuzz root directory
::

@echo off

echo installing litefuzz deps and setup on Windows...
echo.

::
:: install chocolatey package manager
::
:: source: https://stackoverflow.com/questions/52578270/install-python-with-cmd-or-powershell
::

echo ^> fetching chocolatey package manager
echo.

@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"

echo.
echo ^> installing choco packages

choco install -y python2 gnuwin32-coreutils.install diffutils gsudo make mingw openssl windows-sdk-10-version-2004-windbg

echo.
echo ^> installing python dependencies

C:\Python27\Scripts\pip.exe install -r requirements\requirements-py2.txt

echo.
echo ^> disabling windows error reporting

@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "Disable-WindowsErrorReporting"

echo.
echo ^> making test crash apps

cd test\windows
make
cd ..\..

echo.
echo finished!
