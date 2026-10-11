$ErrorActionPreference='Stop'
$b='C:\Windows\Temp\assist-native-rax-20261010'
Copy-Item -LiteralPath 'C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154\native-cold-loader-before-trace.rs' -Destination ($b+'\native-cold-loader-before-trace.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-cold-loader-before-trace.rs')).Hash -ne '170E747E9B99D38F9F02A4066D8D0F8DB7C3DAD52CFCFB8BC87277CB7538EAEA'){throw 'source hash mismatch'}
& 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1' -Arch arm64 -HostArch arm64
& cmd.exe /d /c 'C:\Windows\Temp\assist-native-rax-20261010\toolchain\bin\rustc.exe --edition=2024 -C target-feature=+crt-static --crate-name native_cold_loader_before C:\Windows\Temp\assist-native-rax-20261010\native-cold-loader-before-trace.rs --extern rax=C:\Windows\Temp\assist-native-rax-20261010\target\debug\deps\librax-e6c413934cad3a8f.rlib -L dependency=C:\Windows\Temp\assist-native-rax-20261010\target\debug\deps -o C:\Windows\Temp\assist-native-rax-20261010\native-cold-loader-before-trace.exe > C:\Windows\Temp\assist-native-rax-20261010\native-cold-loader-before-trace-build.log 2>&1'
if($LASTEXITCODE -ne 0){Get-Content ($b+'\native-cold-loader-before-trace-build.log');exit $LASTEXITCODE}
& cmd.exe /d /c 'C:\Windows\Temp\assist-native-rax-20261010\native-cold-loader-before-trace.exe C:\Windows\Temp\assist-native-rax-20261010\src\tests\fixtures\user\windows\bin\arm64\smoke.exe > C:\Windows\Temp\assist-native-rax-20261010\native-cold-loader-before-trace-output.log 2>&1'
$gateExit=$LASTEXITCODE
foreach($n in @('native-cold-loader-before-trace-output.log','native-cold-loader-before-trace-build.log')){Copy-Item -LiteralPath ($b+'\'+$n) -Destination ('C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154\'+$n);Write-Output ($n+' '+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\'+$n)).Hash)}
exit $gateExit
