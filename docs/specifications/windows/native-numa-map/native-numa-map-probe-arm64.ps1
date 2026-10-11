$ErrorActionPreference='Stop';$b='C:\Windows\Temp\assist-native-rax-20261010';Copy-Item -LiteralPath 'C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154\native-numa-map-probe.cpp' -Destination ($b+'\native-numa-map-probe.cpp');if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-numa-map-probe.cpp')).Hash -ne 'FA16B0705E866FB9BCB7A2D4FD363B716BFA40D0622170DD48519C2ABD0323F7'){throw 'source hash mismatch'};Set-Location $b
& 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1' -Arch arm64 -HostArch arm64
& cmd.exe /d /c 'cl.exe /nologo /std:c++20 /EHsc /MT native-numa-map-probe.cpp /Fe:native-numa-map-probe-arm64.exe > native-numa-map-probe-arm64-build.log 2>&1'
if($LASTEXITCODE -ne 0){Get-Content 'native-numa-map-probe-arm64-build.log';exit $LASTEXITCODE}
& cmd.exe /d /c 'native-numa-map-probe-arm64.exe > native-numa-map-probe-arm64.log 2>&1'
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-numa-map-probe-arm64.log') -Destination 'C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154\native-numa-map-probe-arm64.log'
Write-Output ((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-numa-map-probe-arm64.log')).Hash)
exit $gateExit
