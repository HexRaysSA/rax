$ErrorActionPreference='Stop'
$b='C:\Windows\Temp\assist-native-rax-20261010'
$share='C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154'
Copy-Item -LiteralPath ($share+'\native-loader-entry-probe.cpp') -Destination ($b+'\native-loader-entry-probe.cpp')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-loader-entry-probe.cpp')).Hash -ne 'B6598847230D766BD385B931D0C557E25051A11617320C67FEE9152CC9204FA5'){throw 'source hash mismatch'}
Set-Location $b
& 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1' -Arch x64 -HostArch arm64
& cmd.exe /d /c 'cl.exe /nologo /std:c++20 /EHsc /MT native-loader-entry-probe.cpp /Fe:native-loader-entry-probe-x64.exe > native-loader-entry-probe-x64-build.log 2>&1'
if($LASTEXITCODE -ne 0){Get-Content 'native-loader-entry-probe-x64-build.log';exit $LASTEXITCODE}
& cmd.exe /d /c 'native-loader-entry-probe-x64.exe C:\Windows\Temp\assist-native-rax-20261010\src\tests\fixtures\user\windows\bin\x64\smoke.exe > native-loader-entry-probe-x64.log 2>&1'
$gateExit=$LASTEXITCODE
foreach($name in @('native-loader-entry-probe-x64.log','native-loader-entry-probe-x64-build.log')){Copy-Item -LiteralPath ($b+'\'+$name) -Destination ($share+'\'+$name);Write-Output ($name+' '+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\'+$name)).Hash)}
exit $gateExit
