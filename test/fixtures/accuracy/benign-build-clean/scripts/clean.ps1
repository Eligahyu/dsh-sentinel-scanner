# Benign PowerShell cleanup. Static fixture; never executed by the scanner.
Remove-Item -Recurse -Force ./dist
Remove-Item -Recurse -Force $env:TEMP\cache
