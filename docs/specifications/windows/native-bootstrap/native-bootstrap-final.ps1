$ErrorActionPreference='Stop'; $b='C:\Windows\Temp\assist-native-rax-20261010'; $s='C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154'
$env:PATH=$b+'\toolchain\bin;'+$env:PATH; $env:RUSTC=$b+'\toolchain\bin\rustc.exe'; $env:CARGO_HOME=$b+'\cargo-home'; $env:CARGO_TARGET_DIR=$b+'\target'
& 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1' -Arch arm64 -HostArch arm64
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\process\start.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\bootstrap-source-0-start.rs') -Destination ($b+'\src\src\user\windows\process\start.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\process\start.rs')).Hash -ne '594DA70046FBED03123703D25414B7B5F1CB017F9C188414E2B16679F36AEBB1'){throw 'source mismatch: src/user/windows/process/start.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\process\thread.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\bootstrap-source-1-thread.rs') -Destination ($b+'\src\src\user\windows\process\thread.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\process\thread.rs')).Hash -ne '37C72833CABE4E082218884635B52F4598A16F3EE592A1A471C9EAA3FDFF4EA2'){throw 'source mismatch: src/user/windows/process/thread.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\process\mod.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\bootstrap-source-2-mod.rs') -Destination ($b+'\src\src\user\windows\process\mod.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\process\mod.rs')).Hash -ne '32B80155DF3FE6E09A17F14AC8FA3F4C72753692746990811EC7D5500A73E259'){throw 'source mismatch: src/user/windows/process/mod.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\process\native_start.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\bootstrap-source-3-native_start.rs') -Destination ($b+'\src\src\user\windows\process\native_start.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\process\native_start.rs')).Hash -ne '5BE69F45D98C32F1E969FD44391008B3773CAECFB849FCF675B2CEBD7E5312AA'){throw 'source mismatch: src/user/windows/process/native_start.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\process\native_start\tests.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\bootstrap-source-4-tests.rs') -Destination ($b+'\src\src\user\windows\process\native_start\tests.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\process\native_start\tests.rs')).Hash -ne 'D4528966026393C59BE195167B7E80632B0F7A8379F87AF9A9704F0D32ECCA42'){throw 'source mismatch: src/user/windows/process/native_start/tests.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\process\sched.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\bootstrap-source-5-sched.rs') -Destination ($b+'\src\src\user\windows\process\sched.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\process\sched.rs')).Hash -ne '7D293A4365D725166EEA0B89698F409ED0483F0C7D62763A31BF641A694201C4'){throw 'source mismatch: src/user/windows/process/sched.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\native.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\bootstrap-source-6-native.rs') -Destination ($b+'\src\src\user\windows\native.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\native.rs')).Hash -ne '196FC678E72A648277975CA17D25A9A0B5A4C327A1DF4D08761BF669BB0FC5A6'){throw 'source mismatch: src/user/windows/native.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($b+'\src\src\user\windows\loader\ldr.rs'))|Out-Null
Copy-Item -LiteralPath ($s+'\bootstrap-source-7-ldr.rs') -Destination ($b+'\src\src\user\windows\loader\ldr.rs')
if((Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\src\src\user\windows\loader\ldr.rs')).Hash -ne 'E53C185D04E45BFA8E0B27CDFCE287470CB13630C224733DF40F32CD0248F206'){throw 'source mismatch: src/user/windows/loader/ldr.rs'}
Set-Location ($b+'\src')
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features --lib native_start -- --nocapture > '+$b+'\native-bootstrap-final-targeted.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-bootstrap-final-targeted.log') -Destination ($s+'\native-bootstrap-final-targeted.log')
Write-Output ('gate targeted exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-bootstrap-final-targeted.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features --lib -- --nocapture > '+$b+'\native-bootstrap-final-full.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-bootstrap-final-full.log') -Destination ($s+'\native-bootstrap-final-full.log')
Write-Output ('gate full exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-bootstrap-final-full.log')).Hash)
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features -p rax-capi -- --nocapture > '+$b+'\native-bootstrap-final-capi.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-bootstrap-final-capi.log') -Destination ($s+'\native-bootstrap-final-capi.log')
Write-Output ('gate capi exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-bootstrap-final-capi.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
& cmd.exe /d /c ('cargo.exe build --locked --offline --no-default-features --all-targets > '+$b+'\native-bootstrap-final-all-targets.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-bootstrap-final-all-targets.log') -Destination ($s+'\native-bootstrap-final-all-targets.log')
Write-Output ('gate all-targets exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-bootstrap-final-all-targets.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
& cmd.exe /d /c ('cargo.exe test --locked --offline --no-default-features --test user_windows_memory -- --nocapture > '+$b+'\native-bootstrap-final-integration.log 2>&1')
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath ($b+'\native-bootstrap-final-integration.log') -Destination ($s+'\native-bootstrap-final-integration.log')
Write-Output ('gate integration exit='+$gateExit+' sha256='+(Get-FileHash -Algorithm SHA256 -LiteralPath ($b+'\native-bootstrap-final-integration.log')).Hash)
if($gateExit -ne 0){exit $gateExit}
exit 0
