$ErrorActionPreference='Stop'; $b='C:\Windows\Temp\assist-native-rax-20261010'; $s='C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154'
$env:PATH=$b+'\toolchain\bin;'+$env:PATH; $env:RUSTC=$b+'\toolchain\bin\rustc.exe'; $env:CARGO_HOME=$b+'\cargo-home'; $env:CARGO_TARGET_DIR=$b+'\target'
& 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1' -Arch arm64 -HostArch arm64
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\dll\native\query.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\numa-source-0-query.rs') -Destination ($b+'\src\src\user\windows\dll\native\query.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\dll\native\query.rs')).Hash -ne '6898B058B6E635E550E5237F3236BADDBC1190A4A21609073223D9E479298D39'){throw 'source mismatch: src/user/windows/dll/native/query.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\process\sched\tests\services_tests.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\numa-source-1-services_tests.rs') -Destination ($b+'\src\src\user\windows\process\sched\tests\services_tests.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\process\sched\tests\services_tests.rs')).Hash -ne '5089F53AE34603F2305C9DFB59E246FA5A872ED072C9BC26A5CF9968AAA09144'){throw 'source mismatch: src/user/windows/process/sched/tests/services_tests.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\process\sched\tests\services_tests\numa_map_tests.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\numa-source-2-numa_map_tests.rs') -Destination ($b+'\src\src\user\windows\process\sched\tests\services_tests\numa_map_tests.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\process\sched\tests\services_tests\numa_map_tests.rs')).Hash -ne '8D856CD0711A3B89535CEA04B5498AE9FC6C6628AAAE2700B96E32D20819C7B2'){throw 'source mismatch: src/user/windows/process/sched/tests/services_tests/numa_map_tests.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\process\sched\tests\services_tests\numa_map_leaf_tests.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\numa-source-3-numa_map_leaf_tests.rs') -Destination ($b+'\src\src\user\windows\process\sched\tests\services_tests\numa_map_leaf_tests.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\process\sched\tests\services_tests\numa_map_leaf_tests.rs')).Hash -ne '16370E294A2D5829246B236DD247A22FF96D0134BBD55ABCBBD646CBB17E7C23'){throw 'source mismatch: src/user/windows/process/sched/tests/services_tests/numa_map_leaf_tests.rs'}
Set-Location ($b+'\src')
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features --lib numa_map -- --nocapture > '+$b+'\native-numa-final-targeted.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-numa-final-targeted.log') -Destination ($s+'\native-numa-final-targeted.log')
Write-Output ('gate targeted exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-numa-final-targeted.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features --lib -- --nocapture > '+$b+'\native-numa-final-full.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-numa-final-full.log') -Destination ($s+'\native-numa-final-full.log')
Write-Output ('gate full exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-numa-final-full.log')).Hash)
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features -p rax-capi -- --nocapture > '+$b+'\native-numa-final-capi.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-numa-final-capi.log') -Destination ($s+'\native-numa-final-capi.log')
Write-Output ('gate capi exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-numa-final-capi.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
& cmd.exe /d /c ('cargo.exe build --locked --offline --no-default-features --all-targets > '+$b+'\native-numa-final-all-targets.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-numa-final-all-targets.log') -Destination ($s+'\native-numa-final-all-targets.log')
Write-Output ('gate all-targets exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-numa-final-all-targets.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features --test user_windows_memory -- --nocapture > '+$b+'\native-numa-final-integration.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-numa-final-integration.log') -Destination ($s+'\native-numa-final-integration.log')
Write-Output ('gate integration exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-numa-final-integration.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
exit 0
