@echo off
cls
SET CURRENTDIR=%~dp0
SET CMD="& '%CURRENTDIR%Modules\Installer\Install-FindAccountLockout.ps1'"
SET SCRIPT="%CURRENTDIR%Modules\Installer\Install-FindAccountLockout.ps1"


::First we need to verify that the installer was run with admin rights.

::Try to create a test directory inside of the Windows directory (which requires admin rights)
set TESTPATH=%WINDIR%\test_local_admin
rd "%TESTPATH%" > nul 2> nul
md "%TESTPATH%" > nul 2> nul

::Determine whether an error was returned (which would indicate a lack of admin rights)
if [%errorlevel%]==[0] set isadmin=true
if not [%errorlevel%]==[0] set isadmin=false

::Cleanup the test folder
rd "%TESTPATH%" > nul 2> nul

::Run the installer if we have admin rights
if [%isadmin%]==[true] (
   powershell -ExecutionPolicy Bypass -NoProfile -Command %CMD%
)
if not [%isadmin%]==[true] (
   echo Installation failed. User IS NOT admin.
)
pause