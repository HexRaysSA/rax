$env:PATH='C:\Windows\Temp\assist-native-rax-20261010\toolchain\bin;'+$env:PATH; $env:RUSTC='C:\Windows\Temp\assist-native-rax-20261010\toolchain\bin\rustc.exe'; $env:CARGO_HOME='C:\Windows\Temp\assist-native-rax-20261010\cargo-home'; $env:CARGO_TARGET_DIR='C:\Windows\Temp\assist-native-rax-20261010\target'; & 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1' -Arch arm64 -HostArch arm64; 
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName('C:\Windows\Temp\assist-native-rax-20261010\src\src\user\windows\layout.rs'))|Out-Null
Copy-Item -LiteralPath 'C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154\parameters-final-layout.rs' -Destination 'C:\Windows\Temp\assist-native-rax-20261010\src\src\user\windows\layout.rs'
if((Get-FileHash -Algorithm SHA256 'C:\Windows\Temp\assist-native-rax-20261010\src\src\user\windows\layout.rs').Hash -ne '07EC74698367E9171241FD35087E9B04DD4A7C41BC2F9AD71B16FEB1AE88B417'){throw 'source hash mismatch: src/user/windows/layout.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName('C:\Windows\Temp\assist-native-rax-20261010\src\src\user\windows\process\start.rs'))|Out-Null
Copy-Item -LiteralPath 'C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154\parameters-final-start.rs' -Destination 'C:\Windows\Temp\assist-native-rax-20261010\src\src\user\windows\process\start.rs'
if((Get-FileHash -Algorithm SHA256 'C:\Windows\Temp\assist-native-rax-20261010\src\src\user\windows\process\start.rs').Hash -ne '7033D0BA0BC4891270E3B624AC6F10DC7D9B2D6389CE9199135D449C41CDEDC5'){throw 'source hash mismatch: src/user/windows/process/start.rs'}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName('C:\Windows\Temp\assist-native-rax-20261010\src\src\user\windows\process\start\parameters_tests.rs'))|Out-Null
Copy-Item -LiteralPath 'C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154\parameters-final-parameters_tests.rs' -Destination 'C:\Windows\Temp\assist-native-rax-20261010\src\src\user\windows\process\start\parameters_tests.rs'
if((Get-FileHash -Algorithm SHA256 'C:\Windows\Temp\assist-native-rax-20261010\src\src\user\windows\process\start\parameters_tests.rs').Hash -ne '71A6C2C0AF9D1FC7AE20D42B7E1EFB3789A8D859C4B95F4BAA9CA28A07E604D1'){throw 'source hash mismatch: src/user/windows/process/start/parameters_tests.rs'}
Set-Location 'C:\Windows\Temp\assist-native-rax-20261010\src'
& cmd.exe /d /c 'cargo.exe test --locked --offline --no-default-features --lib -- --nocapture > C:\Windows\Temp\assist-native-rax-20261010\native-parameters-resumed-full.log 2>&1'
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath 'C:\Windows\Temp\assist-native-rax-20261010\native-parameters-resumed-full.log' -Destination 'C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154\native-parameters-resumed-full.log'
Write-Output ('native-parameters-resumed-full.log '+(Get-FileHash -Algorithm SHA256 'C:\Windows\Temp\assist-native-rax-20261010\native-parameters-resumed-full.log').Hash)
if($gateExit -ne 0 -and 'full' -ne 'full'){exit $gateExit}
& cmd.exe /d /c 'cargo.exe test --locked --offline --no-default-features -p rax-capi -- --nocapture > C:\Windows\Temp\assist-native-rax-20261010\native-parameters-resumed-capi.log 2>&1'
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath 'C:\Windows\Temp\assist-native-rax-20261010\native-parameters-resumed-capi.log' -Destination 'C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154\native-parameters-resumed-capi.log'
Write-Output ('native-parameters-resumed-capi.log '+(Get-FileHash -Algorithm SHA256 'C:\Windows\Temp\assist-native-rax-20261010\native-parameters-resumed-capi.log').Hash)
if($gateExit -ne 0 -and 'capi' -ne 'full'){exit $gateExit}
& cmd.exe /d /c 'cargo.exe build --locked --offline --no-default-features --all-targets > C:\Windows\Temp\assist-native-rax-20261010\native-parameters-resumed-all-targets.log 2>&1'
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath 'C:\Windows\Temp\assist-native-rax-20261010\native-parameters-resumed-all-targets.log' -Destination 'C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154\native-parameters-resumed-all-targets.log'
Write-Output ('native-parameters-resumed-all-targets.log '+(Get-FileHash -Algorithm SHA256 'C:\Windows\Temp\assist-native-rax-20261010\native-parameters-resumed-all-targets.log').Hash)
if($gateExit -ne 0 -and 'all-targets' -ne 'full'){exit $gateExit}
& cmd.exe /d /c 'cargo.exe test --locked --offline --no-default-features --test user_windows_memory -- --nocapture > C:\Windows\Temp\assist-native-rax-20261010\native-parameters-resumed-integration.log 2>&1'
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath 'C:\Windows\Temp\assist-native-rax-20261010\native-parameters-resumed-integration.log' -Destination 'C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154\native-parameters-resumed-integration.log'
Write-Output ('native-parameters-resumed-integration.log '+(Get-FileHash -Algorithm SHA256 'C:\Windows\Temp\assist-native-rax-20261010\native-parameters-resumed-integration.log').Hash)
if($gateExit -ne 0 -and 'integration' -ne 'full'){exit $gateExit}
exit 0
