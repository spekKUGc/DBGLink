@echo off
setlocal EnableExtensions
set "MSBUILDDISABLENODEREUSE=1"

set "ROOT=%~dp0.."
set "POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
where pwsh.exe >nul 2>&1
if not errorlevel 1 set "POWERSHELL=pwsh.exe"
set "CONFIGURATION=Release"
set "PACKAGE_OPTION="
set "PACKAGE_ONLY="
set "SKIP_TESTS="
set "CLEAN_AFTER="
REM S-4: the NuGet scratch directory uses a GUID suffix (unpredictable, unlike
REM %RANDOM%) and CreateNew-style creation below â€” fail closed if the path
REM already exists instead of reusing (and later deleting) someone else's tree.
REM The GUID is read back from a file: cmd's `for /f` strips the nested quotes
REM of a quoted executable path, so `for /f` over such a command never yields
REM a value ("syntax of the file name is incorrect").
set "NUGET_SUFFIX="
"%POWERSHELL%" -NoProfile -Command "[guid]::NewGuid().ToString('N')" > "%TEMP%\dbglink-nuget-suffix.txt"
if not errorlevel 1 set /p NUGET_SUFFIX=<"%TEMP%\dbglink-nuget-suffix.txt"
del "%TEMP%\dbglink-nuget-suffix.txt" >nul 2>&1
if not defined NUGET_SUFFIX (
    echo Could not generate a unique NuGet scratch suffix.
    exit /b 2
)
set "NUGET_SCRATCH=%TEMP%\DBGLinkNuGetScratch-%NUGET_SUFFIX%"
"%POWERSHELL%" -NoProfile -Command "if (Test-Path -LiteralPath $env:NUGET_SCRATCH) { exit 3 }; $dir = [IO.Directory]::CreateDirectory($env:NUGET_SCRATCH); if (($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { exit 3 }"
if errorlevel 1 (
    echo Refusing to reuse an existing NuGet scratch directory: %NUGET_SCRATCH%
    exit /b 2
)
set "NUGET_PACKAGES=%NUGET_SCRATCH%"
set "NUGET_CONFIG=%ROOT%\tools\nuget.config"
set "GHIDRA_HOME=%GHIDRA_INSTALL_DIR%"
if not defined GHIDRA_HOME set "GHIDRA_HOME=%DBGLINK_GHIDRA_HOME%"

:parse
if "%~1"=="" goto parsed
if /I "%~1"=="--configuration" (
    if "%~2"=="" goto usage
    set "CONFIGURATION=%~2"
    shift
    shift
    goto parse
)
if /I "%~1"=="--ghidra-home" (
    if "%~2"=="" goto usage
    set "GHIDRA_HOME=%~2"
    shift
    shift
    goto parse
)
if /I "%~1"=="--help" goto help
if /I "%~1"=="--stage-package" (
    set "PACKAGE_OPTION=-StageOnly"
    shift
    goto parse
)
if /I "%~1"=="--package-only" (
    set "PACKAGE_ONLY=1"
    shift
    goto parse
)
if /I "%~1"=="--skip-tests" (
    set "SKIP_TESTS=1"
    shift
    goto parse
)
if /I "%~1"=="--clean" (
    set "CLEAN_AFTER=1"
    shift
    goto parse
)
if /I "%~1"=="-h" goto help
goto usage

:parsed
if /I not "%CONFIGURATION%"=="Debug" if /I not "%CONFIGURATION%"=="Release" goto usage
if defined PACKAGE_ONLY goto skip_ghidra_check
if not defined GHIDRA_HOME (
    echo Set GHIDRA_INSTALL_DIR or pass --ghidra-home ^<path^>.
    exit /b 2
)
if not exist "%GHIDRA_HOME%\ghidraRun.bat" (
    echo Ghidra installation was not found: %GHIDRA_HOME%
    exit /b 2
)
:skip_ghidra_check

REM Package-only reuses the current build outputs and needs neither MSBuild nor
REM Gradle. Jump straight to the package stage; the artifacts are validated by
REM package.ps1 with a clear "run tools\build.cmd first" message.
if defined PACKAGE_ONLY (
    pushd "%ROOT%"
    goto package_stage
)

set "MSBUILD="
where msbuild.exe >nul 2>&1
if not errorlevel 1 goto msbuild_ready
    set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
    if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
    if not exist "%VSWHERE%" (
        echo MSBuild was not found. Start from a Visual Studio Developer Prompt or install Visual Studio with C++ Desktop.
        exit /b 2
    )
    set "VSINSTALL="
    REM Same as above: the vswhere path contains a space, so the output is
    REM read back from a file instead of through `for /f`.
    "%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath > "%TEMP%\dbglink-vswhere.txt"
    if not errorlevel 1 set /p VSINSTALL=<"%TEMP%\dbglink-vswhere.txt"
    del "%TEMP%\dbglink-vswhere.txt" >nul 2>&1
    if not defined VSINSTALL (
        echo A Visual Studio installation with the C++ workload was not found.
        exit /b 2
    )
    set "MSBUILD=%VSINSTALL%\MSBuild\Current\Bin\MSBuild.exe"
    if not exist "%MSBUILD%" (
        echo MSBuild was not found in the selected Visual Studio installation.
        exit /b 2
    )
:msbuild_ready
if not defined MSBUILD set "MSBUILD=msbuild.exe"

if not exist "%ROOT%\tools\run-clean-env.ps1" (
    echo The clean build environment helper was not found.
    exit /b 2
)

pushd "%ROOT%"
echo [build] DBGLink %CONFIGURATION% - managed and native outputs...
"%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File tools\run-clean-env.ps1 -FilePath "%MSBUILD%" -ArgumentList "src\mcp\DbgLink.Server\DbgLink.Server.csproj /t:Restore /p:RestoreConfigFile=\"%NUGET_CONFIG%\" /p:RestoreIgnoreFailedSources=true /p:MSBuildEnableWorkloadResolver=false /v:minimal"
if errorlevel 1 goto failed
"%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File tools\run-clean-env.ps1 -FilePath "%MSBUILD%" -ArgumentList "src\launcher\DbgLink.Launcher.Core\DbgLink.Launcher.Core.csproj /t:Restore /p:RestoreConfigFile=\"%NUGET_CONFIG%\" /p:RestoreIgnoreFailedSources=true /p:MSBuildEnableWorkloadResolver=false /v:minimal"
if errorlevel 1 goto failed
"%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File tools\run-clean-env.ps1 -FilePath "%MSBUILD%" -ArgumentList "src\launcher\DbgLink.Launcher.Cli\DbgLink.Launcher.Cli.csproj /t:Restore /p:RestoreConfigFile=\"%NUGET_CONFIG%\" /p:RestoreIgnoreFailedSources=true /p:MSBuildEnableWorkloadResolver=false /v:minimal"
if errorlevel 1 goto failed
"%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File tools\run-clean-env.ps1 -FilePath "%MSBUILD%" -ArgumentList "tests\DbgLink.Tests\DbgLink.Tests.csproj /t:Restore /p:RestoreConfigFile=\"%NUGET_CONFIG%\" /p:RestoreIgnoreFailedSources=true /p:MSBuildEnableWorkloadResolver=false /v:minimal"
if errorlevel 1 goto failed

"%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File tools\run-clean-env.ps1 -FilePath "%MSBUILD%" -ArgumentList "DbgLink.sln /t:Build /p:Configuration=%CONFIGURATION% /p:Platform=x64 /p:RestoreConfigFile=\"%NUGET_CONFIG%\" /p:RestoreIgnoreFailedSources=true /m:1 /v:minimal"
if errorlevel 1 goto failed

if not exist "bin\native-tests\x64\%CONFIGURATION%\DbgLink.Native.Json.Tests.exe" (
    echo Native JSON test harness was not built.
    goto failed
)
if defined SKIP_TESTS goto after_native_x64
"bin\native-tests\x64\%CONFIGURATION%\DbgLink.Native.Json.Tests.exe"
if errorlevel 1 goto failed
:after_native_x64

"%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File tools\run-clean-env.ps1 -FilePath "%MSBUILD%" -ArgumentList "src\native\DbgLink.Native\DbgLink.Native.vcxproj /t:Build /p:Configuration=%CONFIGURATION% /p:Platform=Win32 /m:1 /v:minimal"
if errorlevel 1 goto failed

REM The 32-bit native test harness compiles the x86 ABI branches that the x64
REM run never executes, so it is built and run here as well.
"%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File tools\run-clean-env.ps1 -FilePath "%MSBUILD%" -ArgumentList "tests\DbgLink.Native.Tests\DbgLink.Native.Tests.vcxproj /t:Build /p:Configuration=%CONFIGURATION% /p:Platform=Win32 /m:1 /v:minimal"
if errorlevel 1 goto failed
if not exist "bin\native-tests\Win32\%CONFIGURATION%\DbgLink.Native.Json.Tests.exe" (
    echo Native Win32 JSON test harness was not built.
    goto failed
)
if defined SKIP_TESTS goto after_native_win32
"bin\native-tests\Win32\%CONFIGURATION%\DbgLink.Native.Json.Tests.exe"
if errorlevel 1 goto failed
:after_native_win32

"%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File tools\run-clean-env.ps1 -FilePath "%MSBUILD%" -ArgumentList "tests\fixtures\AnalysisTarget.vcxproj /t:Build /p:Configuration=Release /p:Platform=x64 /m:1 /v:minimal"
if errorlevel 1 goto failed
"%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File tools\run-clean-env.ps1 -FilePath "%MSBUILD%" -ArgumentList "tests\fixtures\AnalysisTarget.vcxproj /t:Build /p:Configuration=Release /p:Platform=Win32 /m:1 /v:minimal"
if errorlevel 1 goto failed

"%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File tools\run-clean-env.ps1 -FilePath "%MSBUILD%" -ArgumentList "tests\DbgLink.Tests\DbgLink.Tests.csproj /t:Build /p:Configuration=%CONFIGURATION% /p:RestoreConfigFile=\"%NUGET_CONFIG%\" /p:MSBuildEnableWorkloadResolver=false /v:minimal"
if errorlevel 1 goto failed
if defined SKIP_TESTS goto after_managed_tests
echo [test] managed suite...
"%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File tools\run-clean-env.ps1 -FilePath dotnet -ArgumentList "test tests\DbgLink.Tests\DbgLink.Tests.csproj --configuration %CONFIGURATION% --no-build --no-restore -m:1 --logger \"console;verbosity=minimal\""
if errorlevel 1 goto failed
:after_managed_tests

echo [publish] self-contained server and launcher...
"%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File tools\remove-build-directory.ps1 -Kind publish
if errorlevel 1 goto failed
REM The publish restore uses a win-x64 RID plus single-file, which would add
REM RID/ILLink entries to packages.lock.json. Park the lock files around the
REM two publishes so the committed (RID-free) state is what a plain
REM `dotnet test` and this script both leave behind.
call :park_locks
"%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File tools\run-clean-env.ps1 -FilePath dotnet -ArgumentList "publish src\mcp\DbgLink.Server\DbgLink.Server.csproj --configuration %CONFIGURATION% --runtime win-x64 --self-contained true --configfile \"%NUGET_CONFIG%\" --output bin\publish\DbgLink.Server -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -p:DebugSymbols=false -p:MSBuildEnableWorkloadResolver=false"
if errorlevel 1 goto failed
"%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File tools\run-clean-env.ps1 -FilePath dotnet -ArgumentList "publish src\launcher\DbgLink.Launcher.Cli\DbgLink.Launcher.Cli.csproj --configuration %CONFIGURATION% --runtime win-x64 --self-contained true --configfile \"%NUGET_CONFIG%\" --output bin\publish\DbgLink.Launcher.Cli -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -p:DebugSymbols=false -p:MSBuildEnableWorkloadResolver=false"
if errorlevel 1 goto failed
call :unpark_locks

set "GRADLE_CMD=%GHIDRA_HOME%\support\gradle\gradlew.bat"
if not exist "%GRADLE_CMD%" (
    echo Ghidra Gradle wrapper was not found: %GRADLE_CMD%
    exit /b 2
)
echo [extension] Ghidra bridge zip...
"%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File tools\run-gradle.ps1 -WrapperPath "%GRADLE_CMD%" -ProjectPath src\ghidra\GhidraBridge -GhidraHome "%GHIDRA_HOME%"
if errorlevel 1 goto failed

:package_stage
echo [package] assembling the self-contained bundle...
"%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File tools\package.ps1 -Configuration "%CONFIGURATION%" %PACKAGE_OPTION%
if errorlevel 1 goto failed

REM Keep bin\publish, the native outputs and the Gradle zip by default so a
REM later --package-only run does not need a full rebuild. --clean restores the
REM old wipe-everything behaviour.
if not defined CLEAN_AFTER goto after_clean
echo [clean] removing transient build outputs...
"%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File tools\clean-transient.ps1
if errorlevel 1 goto failed
:after_clean

if defined PACKAGE_OPTION (echo Build complete. Self-contained package: %CD%\artifacts\pending) else (echo Build complete. Self-contained package: %CD%\artifacts\current)
call :cleanup_scratch
popd
exit /b 0

:failed
set "EXIT_CODE=%ERRORLEVEL%"
call :unpark_locks
call :cleanup_scratch
popd
echo Build failed with exit code %EXIT_CODE%.
exit /b %EXIT_CODE%

:park_locks
for %%P in (src\mcp\DbgLink.Server src\launcher\DbgLink.Launcher.Core src\launcher\DbgLink.Launcher.Cli) do (
    if exist "%%P\packages.lock.json" if not exist "%%P\packages.lock.json.park" move /y "%%P\packages.lock.json" "%%P\packages.lock.json.park" >nul
)
exit /b 0

:unpark_locks
for %%P in (src\mcp\DbgLink.Server src\launcher\DbgLink.Launcher.Core src\launcher\DbgLink.Launcher.Cli) do (
    if exist "%%P\packages.lock.json.park" move /y "%%P\packages.lock.json.park" "%%P\packages.lock.json" >nul
)
exit /b 0

:cleanup_scratch
"%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File tools\remove-build-directory.ps1 -Kind nuget
exit /b 0

:usage
echo Usage: tools\build.cmd [--configuration Debug^|Release] [--ghidra-home ^<path^>]
echo        [--skip-tests] [--package-only] [--stage-package] [--clean]
echo Builds all components, publishes self-contained single-file launchers, and refreshes artifacts\current.
echo Without --ghidra-home, GHIDRA_INSTALL_DIR or DBGLINK_GHIDRA_HOME must be set.
echo   --skip-tests    build and publish, but do not run the managed/native test suites.
echo   --package-only  repackage existing outputs; no MSBuild, Gradle or GHIDRA_HOME needed.
echo   --stage-package write artifacts\pending instead of artifacts\current.
echo   --clean         delete bin and the Gradle dist after a successful package.
exit /b 2

:help
echo Usage: tools\build.cmd [--configuration Debug^|Release] [--ghidra-home ^<path^>]
echo        [--skip-tests] [--package-only] [--stage-package] [--clean]
echo Builds all components, publishes self-contained single-file launchers, and refreshes artifacts\current.
echo Without --ghidra-home, GHIDRA_INSTALL_DIR or DBGLINK_GHIDRA_HOME must be set.
echo   --skip-tests    build and publish, but do not run the managed/native test suites.
echo   --package-only  repackage existing outputs; no MSBuild, Gradle or GHIDRA_HOME needed.
echo   --stage-package write artifacts\pending instead of artifacts\current.
echo   --clean         delete bin and the Gradle dist after a successful package.
exit /b 0
