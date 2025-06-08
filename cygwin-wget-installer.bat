
:: <# BEGIN POWERSHELL AS BATCH HEADER
@ECHO OFF
copy %~s0 %~s0.ps1 >nul
PowerShell.exe -ExecutionPolicy Unrestricted -NoProfile -Command function :: {}; %~s0.ps1 '%1' '%2'
del %~s0.ps1 >nul
GOTO :EOF
:: END POWERSHELL AS BATCH HEADER #>

# install-cygwin-wget.ps1
. {
Invoke-WebRequest `
  -Uri https://cygwin.com/setup-x86_64.exe `
  -OutFile $env:USERPROFILE\Downloads\setup-x86_64.exe

# Use Start-Process with -Wait to actually wait for completion
Start-Process -FilePath "$env:USERPROFILE\Downloads\setup-x86_64.exe" `
             -ArgumentList "-q", "-A", "-s", "https://mirrors.kernel.org/sourceware/cygwin", "-R", "C:\cygwin64", "-P", "wget,mintty" `
             -Wait -NoNewWindow

Write-Host "Cygwin installation complete. Launching terminal..."

# Now safe to launch the terminal since installation is actually finished
& "C:\cygwin64\bin\mintty.exe" /bin/bash

} @Args
