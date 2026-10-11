$ErrorActionPreference='Stop'
$b='C:\Windows\Temp\assist-native-rax-20261010'
$share='C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154'
Copy-Item -LiteralPath ($share+'\native-startup-probe.cpp') -Destination ($b+'\native-startup-probe.cpp')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-startup-probe.cpp')).Hash -ne '6B086325E80731E2AE04AFD641A39C712206A9C65FC11B69F13B9DB81DA49B7F'){throw 'source hash mismatch'}
Set-Location $b
& 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1' -Arch arm64 -HostArch arm64
& cmd.exe /d /c 'cl.exe /nologo /std:c++20 /EHsc /MT native-startup-probe.cpp /Fe:native-startup-probe-arm64.exe > native-startup-probe-arm64-build.log 2>&1'
if($LASTEXITCODE -ne 0){Get-Content 'native-startup-probe-arm64-build.log';exit $LASTEXITCODE}
& cmd.exe /d /c 'native-startup-probe-arm64.exe C:\Windows\Temp\assist-native-rax-20261010\src\tests\fixtures\user\windows\bin\arm64\smoke.exe > native-startup-probe-arm64.log 2>&1'
$gateExit=$LASTEXITCODE
foreach($name in @('native-startup-probe-arm64.log','native-startup-probe-arm64-build.log')){Copy-Item -LiteralPath ($b+'\'+$name) -Destination ($share+'\'+$name);Write-Output ($name+' '+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\'+$name)).Hash)}
exit $gateExit
