$ErrorActionPreference='Stop';$b='C:\Windows\Temp\assist-native-rax-20261010';Copy-Item -LiteralPath 'C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154\native-hypervisor-page-probe.cpp' -Destination ($b+'\native-hypervisor-page-probe.cpp');if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-hypervisor-page-probe.cpp')).Hash -ne '61CE0759F8E2F6F3FDB072A251DDF6686CC7A8947489B3486DC2C43A2CCDDA68'){throw 'source hash mismatch'};Set-Location $b
& 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1' -Arch x86 -HostArch arm64
& cmd.exe /d /c 'cl.exe /nologo /std:c++20 /EHsc /MT native-hypervisor-page-probe.cpp /Fe:native-hypervisor-page-probe-x86.exe > native-hypervisor-page-probe-x86-build.log 2>&1'
if($LASTEXITCODE -ne 0){Get-Content 'native-hypervisor-page-probe-x86-build.log';exit $LASTEXITCODE}
& cmd.exe /d /c 'native-hypervisor-page-probe-x86.exe > native-hypervisor-page-probe-x86.log 2>&1'
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-hypervisor-page-probe-x86.log') -Destination 'C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154\native-hypervisor-page-probe-x86.log'
Write-Output ((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-hypervisor-page-probe-x86.log')).Hash)
exit $gateExit
