$env:PATH='C:\Windows\Temp\assist-native-rax-20261010\toolchain\bin;'+$env:PATH; $env:RUSTC='C:\Windows\Temp\assist-native-rax-20261010\toolchain\bin\rustc.exe'; $env:CARGO_HOME='C:\Windows\Temp\assist-native-rax-20261010\cargo-home'; $env:CARGO_TARGET_DIR='C:\Windows\Temp\assist-native-rax-20261010\target'; & 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1' -Arch arm64 -HostArch arm64; 
$env:PATH='C:\Windows\Temp\assist-native-rax-20261010\llvm\bin;'+$env:PATH
$env:ASSIST_RESOURCE_PYTHON='C:\Windows\Temp\assist-native-rax-20261010\python\python.exe'
$env:RUSTFLAGS='-C target-feature=+crt-static'

Set-Location 'C:\Windows\Temp\assist-native-rax-20261010\assist\rust\assist-rs'
& cmd.exe /d /c 'cargo.exe clean --package assist-rs --package rax-capi > C:\Windows\Temp\assist-native-rax-20261010\assist-native-topology-reviewed-clean.log 2>&1'
if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
& cmd.exe /d /c 'cargo.exe build --locked --offline --features rax > C:\Windows\Temp\assist-native-rax-20261010\assist-native-topology-reviewed-shipping.log 2>&1'
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath 'C:\Windows\Temp\assist-native-rax-20261010\assist-native-topology-reviewed-shipping.log' -Destination 'C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154\assist-native-topology-reviewed-shipping.log'
Write-Output ('assist-native-topology-reviewed-shipping.log '+(Get-FileHash -Algorithm SHA256 'C:\Windows\Temp\assist-native-rax-20261010\assist-native-topology-reviewed-shipping.log').Hash)
if($gateExit -ne 0){exit $gateExit}
& cmd.exe /d /c 'C:\Windows\Temp\assist-native-rax-20261010\python\python.exe C:\Windows\Temp\assist-native-rax-20261010\assist\assist-cpp-build.py > C:\Windows\Temp\assist-native-rax-20261010\assist-native-topology-reviewed-cpp.log 2>&1'
$gateExit=$LASTEXITCODE
Copy-Item -LiteralPath 'C:\Windows\Temp\assist-native-rax-20261010\assist-native-topology-reviewed-cpp.log' -Destination 'C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154\assist-native-topology-reviewed-cpp.log'
Write-Output ('assist-native-topology-reviewed-cpp.log '+(Get-FileHash -Algorithm SHA256 'C:\Windows\Temp\assist-native-rax-20261010\assist-native-topology-reviewed-cpp.log').Hash)
if($gateExit -ne 0){exit $gateExit}
Copy-Item -LiteralPath 'C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154\native-topology-after-trace.rs' -Destination 'C:\Windows\Temp\assist-native-rax-20261010\native-topology-after-trace.rs'
Set-Location 'C:\Windows\Temp\assist-native-rax-20261010\assist\rust\assist-rs'
& cmd.exe /d /c 'cargo.exe build --locked --offline --features rax --message-format=json > C:\Windows\Temp\assist-native-rax-20261010\native-topology-after-artifacts.jsonl 2> C:\Windows\Temp\assist-native-rax-20261010\native-topology-after-artifacts-stderr.log'
if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
$rlib=$null
foreach($line in (Get-Content 'C:\Windows\Temp\assist-native-rax-20261010\native-topology-after-artifacts.jsonl')){
 $j=$line|ConvertFrom-Json
 if($j.reason -eq 'compiler-artifact' -and $j.target.name -eq 'rax' -and $j.manifest_path -notlike '*\capi\Cargo.toml'){
  foreach($f in $j.filenames){if($f.EndsWith('.rlib')){$rlib=$f}}
 }
}
if(!$rlib){throw 'no current RAX rlib artifact'}
Write-Output ('validated rlib: '+$rlib)
& cmd.exe /d /c ('rustc.exe --edition=2024 -C target-feature=+crt-static --crate-name native_startup_diagnostic C:\Windows\Temp\assist-native-rax-20261010\native-topology-after-trace.rs --extern "rax='+$rlib+'" -L dependency=C:\Windows\Temp\assist-native-rax-20261010\target\debug\deps -o C:\Windows\Temp\assist-native-rax-20261010\native-topology-after-trace.exe > C:\Windows\Temp\assist-native-rax-20261010\native-topology-after-trace-build.log 2>&1')
if($LASTEXITCODE -ne 0){Get-Content 'C:\Windows\Temp\assist-native-rax-20261010\native-topology-after-trace-build.log';exit $LASTEXITCODE}
& cmd.exe /d /c 'C:\Windows\Temp\assist-native-rax-20261010\native-topology-after-trace.exe C:\Windows\Temp\assist-native-rax-20261010\src\tests\fixtures\user\windows\bin\arm64\smoke.exe > C:\Windows\Temp\assist-native-rax-20261010\native-topology-after-trace-output.log 2>&1'
$traceExit=$LASTEXITCODE
if($traceExit -ne 0){exit $traceExit}

Set-Location 'C:\Windows\Temp\assist-native-rax-20261010\assist'
& cl.exe /nologo /std:c++20 /MT /EHsc /utf-8 /DNOMINMAX /Iinclude /Ivendor/rax/capi/include /Ijson native-process-probe.cpp src/emulation/rax/rax_process.cpp ../target/debug/assist_rs.lib ws2_32.lib userenv.lib ntdll.lib bcrypt.lib advapi32.lib /Fe:native-cpp/native-process-probe.exe
if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
& cmd.exe /d /c 'native-cpp\native-process-probe.exe > C:\Windows\Temp\assist-native-rax-20261010\native-topology-after-ordinary-processes.log 2>&1'
$probeExit=$LASTEXITCODE
exit $probeExit
