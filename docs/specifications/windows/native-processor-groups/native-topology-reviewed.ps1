$ErrorActionPreference='Stop'; $b='C:\Windows\Temp\assist-native-rax-20261010'; $s='C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154'
$env:PATH=$b+'\toolchain\bin;'+$env:PATH; $env:RUSTC=$b+'\toolchain\bin\rustc.exe'; $env:CARGO_HOME=$b+'\cargo-home'; $env:CARGO_TARGET_DIR=$b+'\target'
& 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1' -Arch arm64 -HostArch arm64
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\dll\native.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\topology-source-0-native.rs') -Destination ($b+'\src\src\user\windows\dll\native.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\dll\native.rs')).Hash -ne '1AE5A46807C7034B9CD293A0CABAAF6FEE0E6EE1034499BB47DD001FD5A5DFBE'){throw 'source mismatch: src/user/windows/dll/native.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\dll\native\topology.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\topology-source-1-topology.rs') -Destination ($b+'\src\src\user\windows\dll\native\topology.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\dll\native\topology.rs')).Hash -ne 'C37F0BE3ECC619DBFC2772FFC5F1DAB48DA1F19F992EB4D395C9A31342CBD2E2'){throw 'source mismatch: src/user/windows/dll/native/topology.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\process\sched\tests\services_tests.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\topology-source-2-services_tests.rs') -Destination ($b+'\src\src\user\windows\process\sched\tests\services_tests.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\process\sched\tests\services_tests.rs')).Hash -ne '7AC99C04C200A5C856D6593D12F8DB20577685C4CE429349B7492193A9DC0272'){throw 'source mismatch: src/user/windows/process/sched/tests/services_tests.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\process\sched\tests\services_tests\topology_tests.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\topology-source-3-topology_tests.rs') -Destination ($b+'\src\src\user\windows\process\sched\tests\services_tests\topology_tests.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\process\sched\tests\services_tests\topology_tests.rs')).Hash -ne 'E7DB0829DD433FC09262384490A54E502CA1B187A4D1F09A88C04C106AFABF3C'){throw 'source mismatch: src/user/windows/process/sched/tests/services_tests/topology_tests.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\process\sched\tests\services_tests\topology_leaf_tests.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\topology-source-4-topology_leaf_tests.rs') -Destination ($b+'\src\src\user\windows\process\sched\tests\services_tests\topology_leaf_tests.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\process\sched\tests\services_tests\topology_leaf_tests.rs')).Hash -ne '3A6F5067CDDC45BB11CEEA91A5E6B73FBFB6B4550015DAC6831E3CF47F90B4E4'){throw 'source mismatch: src/user/windows/process/sched/tests/services_tests/topology_leaf_tests.rs'}
Set-Location ($b+'\src')
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features --lib group_topology -- --nocapture > '+$b+'\native-topology-reviewed-targeted.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-topology-reviewed-targeted.log') -Destination ($s+'\native-topology-reviewed-targeted.log')
Write-Output ('gate targeted exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-topology-reviewed-targeted.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features --lib -- --nocapture > '+$b+'\native-topology-reviewed-full.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-topology-reviewed-full.log') -Destination ($s+'\native-topology-reviewed-full.log')
Write-Output ('gate full exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-topology-reviewed-full.log')).Hash)
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features -p rax-capi -- --nocapture > '+$b+'\native-topology-reviewed-capi.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-topology-reviewed-capi.log') -Destination ($s+'\native-topology-reviewed-capi.log')
Write-Output ('gate capi exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-topology-reviewed-capi.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
& cmd.exe /d /c ('cargo.exe build --locked --offline --no-default-features --all-targets > '+$b+'\native-topology-reviewed-all-targets.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-topology-reviewed-all-targets.log') -Destination ($s+'\native-topology-reviewed-all-targets.log')
Write-Output ('gate all-targets exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-topology-reviewed-all-targets.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features --test user_windows_memory -- --nocapture > '+$b+'\native-topology-reviewed-integration.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-topology-reviewed-integration.log') -Destination ($s+'\native-topology-reviewed-integration.log')
Write-Output ('gate integration exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-topology-reviewed-integration.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
exit 0
