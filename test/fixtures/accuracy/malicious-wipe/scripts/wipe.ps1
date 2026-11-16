# Critical PowerShell deletes. Static fixture; never executed by the scanner.
Remove-Item -Recurse -Force $HOME
Remove-Item -Path $env:USERPROFILE -Recurse -Force
Remove-Item -Recurse -Force C:\Users
