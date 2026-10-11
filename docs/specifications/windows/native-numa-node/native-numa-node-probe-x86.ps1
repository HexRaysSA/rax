$ErrorActionPreference='Stop'
$b='C:\Windows\Temp\assist-native-rax-20261010'
$share='C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154'
Copy-Item -LiteralPath ($share+'\native-numa-node-probe.cpp') -Destination ($b+'\native-numa-node-probe.cpp')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-numa-node-probe.cpp')).Hash -ne '69A0FB52FC44E4CF44EC21D357E57F7906D4D4F575643545992ED889FD40552F'){throw 'source hash mismatch'}
Set-Location $b
& 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1' -Arch x86 -HostArch arm64
& cmd.exe /d /c 'cl.exe /nologo /std:c++20 /MT native-numa-node-probe.cpp /Fe:native-numa-node-probe-x86.exe > native-numa-node-probe-x86-build.log 2>&1'
if($LASTEXITCODE -ne 0){Get-Content 'native-numa-node-probe-x86-build.log';exit $LASTEXITCODE}
& cmd.exe /d /c 'native-numa-node-probe-x86.exe C:\Windows\Temp\assist-native-rax-20261010\src\tests\fixtures\user\windows\bin\arm64\smoke.exe > native-numa-node-probe-x86.log 2>&1'
$gateExit=$LASTEXITCODE
foreach($name in @('native-numa-node-probe-x86.log','native-numa-node-probe-x86-build.log')){Copy-Item -LiteralPath ($b+'\'+$name) -Destination ($share+'\'+$name);Write-Output ($name+' '+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\'+$name)).Hash)}
exit $gateExit
