$ErrorActionPreference='Stop';$b='C:\Windows\Temp\assist-native-rax-20261010';Copy-Item -LiteralPath 'C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154\native-topology-probe.cpp' -Destination ($b+'\native-topology-probe.cpp');if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-topology-probe.cpp')).Hash -ne 'E03E5761E0D94B715F46FA1887C787E8B787F55239EB5AAFFDEA04B76A7F087F'){throw 'source hash mismatch'};Set-Location $b
& 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1' -Arch x86 -HostArch arm64
& cmd.exe /d /c 'cl.exe /nologo /std:c++20 /EHsc /MT native-topology-probe.cpp /Fe:native-topology-probe-x86-laa.exe /link /LARGEADDRESSAWARE > native-topology-probe-x86-laa-build.log 2>&1'
if($LASTEXITCODE -ne 0){Get-Content 'native-topology-probe-x86-laa-build.log';exit $LASTEXITCODE}
& cmd.exe /d /c 'native-topology-probe-x86-laa.exe > native-topology-probe-x86-laa.log 2>&1'
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-topology-probe-x86-laa.log') -Destination 'C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154\native-topology-probe-x86-laa.log'
Write-Output ((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-topology-probe-x86-laa.log')).Hash)
exit $gateExit
