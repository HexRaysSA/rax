$ErrorActionPreference='Stop'; $b='C:\Windows\Temp\assist-native-rax-20261010'; $s='C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154'
$env:PATH=$b+'\toolchain\bin;'+$env:PATH; $env:RUSTC=$b+'\toolchain\bin\rustc.exe'; $env:CARGO_HOME=$b+'\cargo-home'; $env:CARGO_TARGET_DIR=$b+'\target'
& 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1' -Arch arm64 -HostArch arm64
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\dll\native\topology.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\numa-node-source-0.rs') -Destination ($b+'\src\src\user\windows\dll\native\topology.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\dll\native\topology.rs')).Hash -ne '98EEF359BD2C7AE5E59710AA4138B9C04D035C7B09F3AAFA0CECF1881E92712B'){throw 'source mismatch: src/user/windows/dll/native/topology.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\process\sched\tests\services_tests\topology_tests.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\numa-node-source-1.rs') -Destination ($b+'\src\src\user\windows\process\sched\tests\services_tests\topology_tests.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\process\sched\tests\services_tests\topology_tests.rs')).Hash -ne '3FB1CBBF9595114463E6701402A902712BC264F04F0EDD554EAA74CDDBB5EC47'){throw 'source mismatch: src/user/windows/process/sched/tests/services_tests/topology_tests.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\process\sched\tests\services_tests\numa_node_tests.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\numa-node-source-2.rs') -Destination ($b+'\src\src\user\windows\process\sched\tests\services_tests\numa_node_tests.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\process\sched\tests\services_tests\numa_node_tests.rs')).Hash -ne '659B5A76A1C62799D09CB3D1760E40F5400F4D2899737596F379EB43B55D4900'){throw 'source mismatch: src/user/windows/process/sched/tests/services_tests/numa_node_tests.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\process\sched\tests\services_tests\numa_node_leaf_tests.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\numa-node-source-3.rs') -Destination ($b+'\src\src\user\windows\process\sched\tests\services_tests\numa_node_leaf_tests.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\process\sched\tests\services_tests\numa_node_leaf_tests.rs')).Hash -ne 'C35FD3371DEE2DF8E2D8BFDEDBAD89271CE98016A17CFF567F942FCFC66F98C8'){throw 'source mismatch: src/user/windows/process/sched/tests/services_tests/numa_node_leaf_tests.rs'}
Set-Location ($b+'\src')
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features --lib numa_node -- --nocapture > '+$b+'\native-numa-node-final-targeted.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-numa-node-final-targeted.log') -Destination ($s+'\native-numa-node-final-targeted.log')
Write-Output ('gate targeted exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-numa-node-final-targeted.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features --lib -- --nocapture > '+$b+'\native-numa-node-final-full.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-numa-node-final-full.log') -Destination ($s+'\native-numa-node-final-full.log')
Write-Output ('gate full exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-numa-node-final-full.log')).Hash)
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features -p rax-capi -- --nocapture > '+$b+'\native-numa-node-final-capi.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-numa-node-final-capi.log') -Destination ($s+'\native-numa-node-final-capi.log')
Write-Output ('gate capi exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-numa-node-final-capi.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
& cmd.exe /d /c ('cargo.exe build --locked --offline --no-default-features --all-targets > '+$b+'\native-numa-node-final-all-targets.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-numa-node-final-all-targets.log') -Destination ($s+'\native-numa-node-final-all-targets.log')
Write-Output ('gate all-targets exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-numa-node-final-all-targets.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features --test user_windows_memory -- --nocapture > '+$b+'\native-numa-node-final-integration.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-numa-node-final-integration.log') -Destination ($s+'\native-numa-node-final-integration.log')
Write-Output ('gate integration exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-numa-node-final-integration.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
exit 0
