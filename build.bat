@echo off
rem builds the app with the C# compiler that ships with Windows, no other tools needed
setlocal
cd /d %~dp0

set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe
if not exist "%CSC%" (
    echo .NET Framework 4 compiler not found.
    exit /b 1
)

if not exist dist mkdir dist

"%CSC%" /nologo /target:winexe /platform:anycpu /optimize+ ^
    /out:dist\ShortcutVirusRemover.exe ^
    /win32icon:resources\app.ico ^
    /win32manifest:resources\app.manifest ^
    /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:Microsoft.CSharp.dll ^
    /recurse:src\*.cs
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)
echo Build OK: dist\ShortcutVirusRemover.exe
endlocal
