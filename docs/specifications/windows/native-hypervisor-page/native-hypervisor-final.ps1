$ErrorActionPreference='Stop'; $b='C:\Windows\Temp\assist-native-rax-20261010'; $s='C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154'
$env:PATH=$b+'\toolchain\bin;'+$env:PATH; $env:RUSTC=$b+'\toolchain\bin\rustc.exe'; $env:CARGO_HOME=$b+'\cargo-home'; $env:CARGO_TARGET_DIR=$b+'\target'
& 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1' -Arch arm64 -HostArch arm64
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\dll\native\query.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\hypervisor-source-0-query.rs') -Destination ($b+'\src\src\user\windows\dll\native\query.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\dll\native\query.rs')).Hash -ne '027A8C4873C27B07009F91EA274EFCA48723C696361E1EEC98FB136BAD40828B'){throw 'source mismatch: src/user/windows/dll/native/query.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\process\sched\tests\services_tests.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\hypervisor-source-1-services_tests.rs') -Destination ($b+'\src\src\user\windows\process\sched\tests\services_tests.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\process\sched\tests\services_tests.rs')).Hash -ne 'E79DEFC012117F5D72B4A05F35D7168CA438EC297CDD4DD757A0697334A6A0C7'){throw 'source mismatch: src/user/windows/process/sched/tests/services_tests.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\process\sched\tests\services_tests\hypervisor_page_tests.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\hypervisor-source-2-hypervisor_page_tests.rs') -Destination ($b+'\src\src\user\windows\process\sched\tests\services_tests\hypervisor_page_tests.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\process\sched\tests\services_tests\hypervisor_page_tests.rs')).Hash -ne '95D40C7ADDC4CFB32F422701E3A53D7B2C8BC09074831FFFDD119A6434CCD7D7'){throw 'source mismatch: src/user/windows/process/sched/tests/services_tests/hypervisor_page_tests.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\process\sched\tests\services_tests\hypervisor_page_leaf_tests.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\hypervisor-source-3-hypervisor_page_leaf_tests.rs') -Destination ($b+'\src\src\user\windows\process\sched\tests\services_tests\hypervisor_page_leaf_tests.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\process\sched\tests\services_tests\hypervisor_page_leaf_tests.rs')).Hash -ne '511785F1FD5BC15F4E22408F06C3C76877127BDAADBB6F936B366D28C68C3008'){throw 'source mismatch: src/user/windows/process/sched/tests/services_tests/hypervisor_page_leaf_tests.rs'}
Set-Location ($b+'\src')
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features --lib hypervisor_page -- --nocapture > '+$b+'\native-hypervisor-final-targeted.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-hypervisor-final-targeted.log') -Destination ($s+'\native-hypervisor-final-targeted.log')
Write-Output ('gate targeted exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-hypervisor-final-targeted.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features --lib -- --nocapture > '+$b+'\native-hypervisor-final-full.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-hypervisor-final-full.log') -Destination ($s+'\native-hypervisor-final-full.log')
Write-Output ('gate full exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-hypervisor-final-full.log')).Hash)
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features -p rax-capi -- --nocapture > '+$b+'\native-hypervisor-final-capi.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-hypervisor-final-capi.log') -Destination ($s+'\native-hypervisor-final-capi.log')
Write-Output ('gate capi exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-hypervisor-final-capi.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
& cmd.exe /d /c ('cargo.exe build --locked --offline --no-default-features --all-targets > '+$b+'\native-hypervisor-final-all-targets.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-hypervisor-final-all-targets.log') -Destination ($s+'\native-hypervisor-final-all-targets.log')
Write-Output ('gate all-targets exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-hypervisor-final-all-targets.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features --test user_windows_memory -- --nocapture > '+$b+'\native-hypervisor-final-integration.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-hypervisor-final-integration.log') -Destination ($s+'\native-hypervisor-final-integration.log')
Write-Output ('gate integration exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-hypervisor-final-integration.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
exit 0
