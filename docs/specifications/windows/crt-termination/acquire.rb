#!/usr/bin/env ruby
# Byte-preserving primary-reference acquisition. No emulator or fixture build.
require 'digest'
require 'fileutils'
require 'json'
require 'open3'
require 'zlib'
require 'base64'
require 'tmpdir'

ROOT = File.expand_path(__dir__)
DATE = '2026-09-27'
BASELINE = '06e90d4bb41e0390a877819ed41ed98e369558a3'
MINGW = '9b3dd0125792fe94d16cacdc596dbd42fca1b369'
PKG = '/opt/homebrew/Cellar/mingw-w64/14.0.0_3'
ZIG = '/opt/homebrew/Cellar/zig/0.16.0_1/lib/zig/libc'
LLVM = '/Users/int/local/bin'
SDK_VERSION = '10.0.26100.1'
SDK_URL = "https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.cpp/#{SDK_VERSION}/microsoft.windows.sdk.cpp.#{SDK_VERSION}.nupkg"
SDK_BYTES = 155_613_545
SDK_SHA512 = 'ZveRWpfQKpduSRyI9WxRFQ5BpU9XZ+K2BGQ6lZup//PiH+KPFIGFd/QqrvFjh+isrlOOiJ5cNF6IKuZDCh1E7w=='
SOURCES = []

def fetch(url, range = nil)
  argv = ['curl', '--fail', '--silent', '--show-error', '--retry', '2',
          '--connect-timeout', '15', '--max-time', '60']
  argv.concat(['--range', "#{range[0]}-#{range[1]}"]) if range
  bytes, status = Open3.capture2(*argv, url)
  raise "acquisition failed #{url}" unless status.success?
  bytes = bytes.b
  raise "server ignored byte range #{range}" if range && bytes.bytesize != range[1] - range[0] + 1
  bytes
end

def sdk_directory
  tail_start = SDK_BYTES - 65_557
  tail = fetch(SDK_URL, [tail_start, SDK_BYTES - 1])
  end_offset = tail.rindex("PK\x05\x06".b)
  raise 'ZIP end record missing' unless end_offset
  record = tail.byteslice(end_offset, 22).unpack('VvvvvVVv')
  raise 'multi-volume ZIP unsupported' unless record[1] == 0 && record[2] == 0 && record[3] == record[4]
  raise 'unexpected ZIP end offset' unless tail_start + end_offset + 22 + record[7] == SDK_BYTES
  directory = fetch(SDK_URL, [record[6], record[6] + record[5] - 1])
  entries = {}
  offset = 0
  record[4].times do
    header = directory.byteslice(offset, 46).unpack('VvvvvvvVVVvvvvvVV')
    raise 'invalid ZIP central entry' unless header[0] == 0x02014b50
    name = directory.byteslice(offset + 46, header[10])
    entries[name] = { 'member' => name, 'compression_method' => header[4],
                      'crc32' => format('%08x', header[7]),
                      'compressed_bytes' => header[8], 'uncompressed_bytes' => header[9],
                      'local_header_offset' => header[16], 'flags' => header[3] }
    offset += 46 + header[10] + header[11] + header[12]
  end
  raise 'central directory length mismatch' unless offset == directory.bytesize
  [entries, { 'url' => SDK_URL, 'package_version' => SDK_VERSION, 'package_bytes' => SDK_BYTES,
              'central_directory_offset' => record[6], 'central_directory_bytes' => record[5],
              'central_directory_sha256' => Digest::SHA256.hexdigest(directory),
              'members' => entries.length,
              'acquisition' => 'HTTPS byte ranges; ZIP end record, full central directory, per-member header, raw deflate and CRC32 verified; range extraction does not retain the whole package; full-stream SHA-512 verification is recorded separately' }]
end

def sdk_member(entry)
  offset = entry.fetch('local_header_offset')
  header = fetch(SDK_URL, [offset, offset + 29]).unpack('VvvvvvVVVvv')
  raise 'invalid ZIP local header' unless header[0] == 0x04034b50
  raise 'ZIP encryption unsupported' unless header[2] & 1 == 0
  raise 'central/local compression mismatch' unless header[3] == entry.fetch('compression_method')
  name_and_extra = fetch(SDK_URL, [offset + 30, offset + 29 + header[9] + header[10]])
  raise 'central/local member mismatch' unless name_and_extra.byteslice(0, header[9]) == entry.fetch('member')
  data_offset = offset + 30 + header[9] + header[10]
  compressed = fetch(SDK_URL, [data_offset, data_offset + entry.fetch('compressed_bytes') - 1])
  bytes = case entry.fetch('compression_method')
          when 0 then compressed
          when 8
            inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
            begin
              inflater.inflate(compressed) + inflater.finish
            ensure
              inflater.close
            end
          else raise 'unsupported ZIP compression'
          end
  raise 'ZIP uncompressed length mismatch' unless bytes.bytesize == entry.fetch('uncompressed_bytes')
  raise 'ZIP CRC32 mismatch' unless format('%08x', Zlib.crc32(bytes)) == entry.fetch('crc32')
  bytes
end

def verify_sdk_package
  digest = Digest::SHA512.new
  total = 0
  Open3.popen3('curl', '--fail', '--silent', '--show-error', '--retry', '2',
               '--connect-timeout', '15', '--max-time', '60', SDK_URL) do |stdin, stdout, stderr, wait|
    stdin.close
    while (bytes = stdout.read(1_048_576))
      total += bytes.bytesize
      digest.update(bytes)
    end
    errors = stderr.read
    raise "full SDK stream failed #{errors}" unless wait.value.success?
  end
  raise 'changed full SDK package size' unless total == SDK_BYTES
  raise 'changed full SDK package SHA-512' unless Base64.strict_encode64(digest.digest) == SDK_SHA512
  { 'sha512_base64' => SDK_SHA512, 'bytes' => total,
    'digest_source' => 'x-ms-meta-SHA512 returned by publisher CDN package HEAD; .nupkg.sha512 URL returns HTTP 404',
    'verification' => 'Entire HTTPS package streamed through SHA-512 and length checked; no package binary retained; NuGet author/repository signature not verified' }
end

def retain(path, bytes, metadata)
  absolute = File.join(ROOT, path)
  FileUtils.mkdir_p(File.dirname(absolute))
  File.binwrite(absolute, bytes)
  record(path, metadata)
end

def record(path, metadata)
  bytes = File.binread(File.join(ROOT, path))
  SOURCES << metadata.merge('path' => path, 'retrieved' => DATE,
                            'sha256' => Digest::SHA256.hexdigest(bytes), 'bytes' => bytes.bytesize)
end

def publisher_receipt(reference_id, bytes, metadata, inspection_dir)
  # Publisher source is acquired solely into a temporary inspection directory.
  # The repository retains our hash receipt, not the proprietary SDK bytes.
  absolute = File.join(inspection_dir, File.basename(reference_id))
  File.binwrite(absolute, bytes)
  SOURCES << metadata.merge('reference_id' => reference_id,
                            'retention' => 'Temporary inspection input; raw SDK member/license excluded from feature commits',
                            'retrieved' => DATE, 'sha256' => Digest::SHA256.hexdigest(bytes), 'bytes' => bytes.bytesize)
end

def reuse(archive, paths, manifest_name = 'sources.json')
  prior = JSON.parse(File.binread(File.join(ROOT, "../#{archive}/#{manifest_name}")))
  paths.each do |path|
    old = prior.fetch('sources').find { |entry| entry.fetch('path') == path }
    raise "missing old source #{archive}/#{path}" unless old
    relative = "../#{archive}/#{path}"
    bytes = File.binread(File.join(ROOT, relative))
    raise "changed old source #{relative}" unless Digest::SHA256.hexdigest(bytes) == old.fetch('sha256') && (!old['bytes'] || bytes.bytesize == old.fetch('bytes'))
    SOURCES << old.merge('path' => relative, 'bytes' => bytes.bytesize, 'reuse_manifest' => "../#{archive}/#{manifest_name}")
  end
end

def installed(path, input, metadata, ranges = nil)
  bytes = File.binread(input)
  output = ranges ? ranges.flat_map { |first, last| bytes.lines[(first - 1)..(last - 1)] }.join : bytes
  retain(path, output, metadata.merge('input_path' => input,
                                    'input_sha256' => Digest::SHA256.hexdigest(bytes), 'input_bytes' => bytes.bytesize,
                                    'line_ranges_1based_inclusive' => ranges,
                                    'normalization' => 'None; complete bytes or exact line subsequence'))
end

def observe(path, argv, metadata, input = nil, pattern = nil)
  output, status = Open3.capture2(*argv)
  raise "command failed #{argv.inspect}" unless status.success?
  output = output.lines.select { |line| line.match?(Regexp.new(pattern)) }.join if pattern
  raise "empty observation #{path}" if output.empty?
  metadata = metadata.merge('command_argv' => argv, 'selection_regex' => pattern)
  metadata = metadata.merge('input_path' => input, 'input_sha256' => Digest::SHA256.file(input).hexdigest,
                            'input_bytes' => File.size(input)) if input
  retain(path, output, metadata)
end

if ARGV == ['--verify'] || ARGV == ['--verify-network']
  manifest = JSON.parse(File.binread(File.join(ROOT, 'sources.json')))
  counts = { 'retained_hash_size_checks' => 0, 'publisher_source_receipts' => 0, 'installed_input_hashes' => 0,
             'exact_copy_or_extraction_replays' => 0, 'command_replays' => 0, 'network_sdk_member_replays' => 0 }
  inputs = {}
  unavailable = []
  sdk = nil
  if ARGV == ['--verify-network']
    sdk, actual = sdk_directory
    raise 'changed SDK directory' unless actual == manifest.fetch('microsoft_sdk_package')
  end
  manifest.fetch('sources').each do |entry|
    if entry['reference_id']
      counts['publisher_source_receipts'] += 1
      if sdk
        actual = entry['sdk_zip_member'] ? sdk_member(sdk.fetch(entry.fetch('sdk_zip_member').fetch('member'))) : fetch(entry.fetch('source_url'))
        raise "changed publisher source #{entry['reference_id']}" unless Digest::SHA256.hexdigest(actual) == entry.fetch('sha256') && actual.bytesize == entry.fetch('bytes')
        counts['network_sdk_member_replays'] += 1 if entry['sdk_zip_member']
      end
      next
    end
    bytes = File.binread(File.join(ROOT, entry.fetch('path')))
    raise "changed retained bytes #{entry['path']}" unless Digest::SHA256.hexdigest(bytes) == entry.fetch('sha256') && bytes.bytesize == entry.fetch('bytes')
    counts['retained_hash_size_checks'] += 1
    if entry['sdk_zip_member'] && sdk
      raise "changed SDK member #{entry['path']}" unless sdk_member(sdk.fetch(entry.fetch('sdk_zip_member').fetch('member'))) == bytes
      counts['network_sdk_member_replays'] += 1
    end
    input = entry['input_path']
    if input
      unless File.file?(input)
        unavailable << input
        next
      end
      original = File.binread(input)
      raise "changed installed input #{input}" unless Digest::SHA256.hexdigest(original) == entry.fetch('input_sha256')
      inputs[input] = true
      ranges = entry['line_ranges_1based_inclusive']
      if entry['normalization'] == 'None; complete bytes or exact line subsequence'
        expected = ranges ? ranges.flat_map { |first, last| original.lines[(first - 1)..(last - 1)] }.join : original
        raise "changed source extraction #{entry['path']}" unless expected == bytes
        counts['exact_copy_or_extraction_replays'] += 1
      end
    end
    next unless entry['command_argv']
    argv = entry.fetch('command_argv')
    unless File.file?(argv.first)
      unavailable << argv.first
      next
    end
    stdin_entry = entry['command_stdin_sdk_member']
    if stdin_entry
      next unless sdk
      input_bytes = sdk_member(sdk.fetch(stdin_entry.fetch('member')))
      raise "changed SDK observation input #{entry['path']}" unless Digest::SHA256.hexdigest(input_bytes) == entry.fetch('input_sha256')
      actual, status = Open3.capture2(*argv, stdin_data: input_bytes)
    else
      actual, status = Open3.capture2(*argv)
    end
    raise "replay failed #{entry['path']}" unless status.success?
    pattern = entry['selection_regex']
    actual = actual.lines.select { |line| line.match?(Regexp.new(pattern)) }.join if pattern
    raise "changed command output #{entry['path']}" unless actual == bytes
    counts['command_replays'] += 1
  end
  manifest.fetch('tools').each do |tool|
    unless File.file?(tool.fetch('path'))
      unavailable << tool.fetch('path')
      next
    end
    raise "changed tool #{tool['path']}" unless Digest::SHA256.file(tool.fetch('path')).hexdigest == tool.fetch('sha256')
  end
  raise 'changed acquisition script' unless Digest::SHA256.file(__FILE__).hexdigest == manifest.fetch('acquisition_script_sha256')
  counts['installed_input_hashes'] = inputs.length
  raise 'changed full package digest receipt' if sdk && verify_sdk_package != manifest.fetch('microsoft_sdk_full_package_digest')
  counts['unavailable_inputs_or_tools'] = unavailable.uniq
  puts JSON.generate(counts)
  exit
elsif !ARGV.empty?
  abort 'usage: acquire.rb [--verify|--verify-network]'
end

reuse('crt-initializers', %w[microsoft/LICENSE microsoft/LICENSE-CODE microsoft/exit-exit-exit.md
  microsoft/cexit-c-exit.md microsoft/quick-exit1.md microsoft/atexit.md microsoft/onexit-onexit-m.md
  microsoft/internal-crt-globals-and-functions.md microsoft/execute-onexit-table-initialize-onexit-table-register-onexit-function.md
  mingw14/COPYING mingw14/DISCLAIMER.PD mingw14/crtexe.c mingw14/crtdll.c mingw14/onexit_table.c
  mingw14/msvcrt.def.in mingw14/func.def.in zig/COPYING zig/crtexe.c zig/crtdll.c zig/api-ms-win-crt-runtime.def.in])
reuse('crt-onexit', %w[microsoft/dllonexit.md mingw14/onexit.c])
reuse('crt-startup', %w[microsoft/global-state.md zig/ucrtbase-common.def.in])
reuse('crt-stdio', %w[producer/gcc-x86-crt2.o.txt producer/gcc-x64-crt2.o.txt producer/zig-arm64-crt2.obj.txt producer/zig-arm64-libmingw32.lib.txt])
reuse('services/dll-lifecycle', %w[SDK-API-LICENSE WIN32-LICENSE terminating-a-process.md terminateprocess.md dllmain.md])
reuse('services/fibers', %w[SDK-API-LICENSE SDK-API-LICENSE-CODE flsfree.md])
locks = JSON.parse(File.binread(File.join(ROOT, '../services/locks/sources.json')))
%w[critical-section-objects.md].each do |name|
  relative = "../services/locks/#{name}"
  old = locks.fetch('files').find { |entry| entry.fetch('file') == name }
  raise "missing prior lock source #{name}" unless old
  bytes = File.binread(File.join(ROOT, relative))
  raise "changed lock source #{name}" unless Digest::SHA256.hexdigest(bytes) == old.fetch('sha256')
  record(relative, old.merge('reuse_manifest' => '../services/locks/sources.json'))
end
lock_license = locks.fetch('licenses').find { |entry| entry.fetch('retained_file') == 'LICENSE' }
record('../services/locks/LICENSE', lock_license.merge('sha256' => lock_license.fetch('retained_sha256'), 'reuse_manifest' => '../services/locks/sources.json'))

entries, package_metadata = sdk_directory
package_digest = verify_sdk_package
inspection_dir = Dir.mktmpdir('rax-windows-sdk-termination.')
sdk_members = {
  'microsoft-sdk/package.nuspec' => 'Microsoft.Windows.SDK.CPP.nuspec',
  'microsoft-sdk/exit.cpp' => 'c/Source/10.0.26100.0/ucrt/startup/exit.cpp',
  'microsoft-sdk/onexit.cpp' => 'c/Source/10.0.26100.0/ucrt/startup/onexit.cpp',
  'microsoft-sdk/corecrt_startup.h' => 'c/Include/10.0.26100.0/ucrt/corecrt_startup.h',
  'microsoft-sdk/corecrt_terminate.h' => 'c/Include/10.0.26100.0/ucrt/corecrt_terminate.h',
  'microsoft-sdk/process.h' => 'c/Include/10.0.26100.0/ucrt/process.h',
  'microsoft-sdk/corecrt_internal.h' => 'c/Source/10.0.26100.0/ucrt/inc/corecrt_internal.h',
  'microsoft-sdk/locks.cpp' => 'c/Source/10.0.26100.0/ucrt/internal/locks.cpp',
  'microsoft-sdk/appcrt_dllmain.cpp' => 'c/Source/10.0.26100.0/ucrt/dll/appcrt_dllmain.cpp',
  'microsoft-sdk/initialization.cpp' => 'c/Source/10.0.26100.0/ucrt/internal/initialization.cpp',
  'microsoft-sdk/per_thread_data.cpp' => 'c/Source/10.0.26100.0/ucrt/internal/per_thread_data.cpp',
  'microsoft-sdk/win_policies.cpp' => 'c/Source/10.0.26100.0/ucrt/internal/win_policies.cpp',
  'microsoft-sdk/stdio_initializer.cpp' => 'c/Source/10.0.26100.0/ucrt/initializers/stdio_initializer.cpp',
  'microsoft-sdk/fflush.cpp' => 'c/Source/10.0.26100.0/ucrt/stdio/fflush.cpp',
  'microsoft-sdk/closeall.cpp' => 'c/Source/10.0.26100.0/ucrt/stdio/closeall.cpp',
  'microsoft-sdk/_file.cpp' => 'c/Source/10.0.26100.0/ucrt/stdio/_file.cpp',
  'microsoft-sdk/stream.cpp' => 'c/Source/10.0.26100.0/ucrt/stdio/stream.cpp',
  'microsoft-sdk/abort.cpp' => 'c/Source/10.0.26100.0/ucrt/startup/abort.cpp',
  'microsoft-sdk/terminate.cpp' => 'c/Source/10.0.26100.0/ucrt/misc/terminate.cpp'
}
sdk_members.each do |path, member|
  entry = entries.fetch(member)
  publisher_receipt(path, sdk_member(entry), { 'kind' => 'publisher-distributed implementation source/header/package metadata receipt',
                                   'issuer' => 'Microsoft Corporation', 'revision' => 'Windows SDK 10.0.26100.0, NuGet package 10.0.26100.1',
                                   'source_url' => SDK_URL, 'sdk_zip_member' => entry,
                                   'license' => 'Original copyright and notices retained; package license URL in package.nuspec; SDK source is reference material, not emulator implementation',
                                   'normalization' => 'None; exact uncompressed ZIP member bytes' }, inspection_dir)
end
license_url = 'https://download.microsoft.com/download/0/F/F/0FF2B061-47DD-4F55-89B6-FD1D8C44F14D/sdk_license.rtf'
publisher_receipt('microsoft-sdk/sdk_license.rtf', fetch(license_url), {
  'kind' => 'publisher license', 'issuer' => 'Microsoft Corporation',
  'source_url' => license_url, 'canonical_url' => 'https://aka.ms/WinSDKLicenseURL',
  'revision' => 'Mutable URL; retained SHA-256 pins exact retrieved license; version-specific license text identity unknown',
  'normalization' => 'None' }, inspection_dir)

metadata = { 'kind' => 'installed producer source/header; not a Microsoft native oracle',
             'issuer' => 'MinGW-w64 bundled with Zig',
             'revision' => 'Zig 0.16.0 Homebrew 0.16.0_1; bundled MinGW exact upstream commit unknown',
             'license' => 'Public Domain input notice; ../crt-initializers/zig/COPYING retained' }
installed('zig/tls_atexit.c', "#{ZIG}/mingw/crt/tls_atexit.c", metadata)
installed('zig/ucrt_at_quick_exit.c', "#{ZIG}/mingw/misc/ucrt_at_quick_exit.c", metadata)
installed('zig/process-termination-excerpt.h', "#{ZIG}/include/any-windows-any/process.h", metadata, [[1, 5], [40, 69]])
installed('zig/corecrt-startup-excerpt.h', "#{ZIG}/include/any-windows-any/corecrt_startup.h", metadata, [[1, 5], [18, 25], [61, 68]])

{
  'tls_atexit.c' => 'crt/tls_atexit.c', 'ucrt_at_quick_exit.c' => 'misc/ucrt_at_quick_exit.c',
  'process.h' => '../mingw-w64-headers/crt/process.h',
  'ucrtbase-common.def.in' => 'lib-common/ucrtbase-common.def.in',
  'api-ms-win-crt-runtime.def.in' => 'lib-common/api-ms-win-crt-runtime-l1-1-0.def.in'
}.each do |name, source|
  upstream = source.start_with?('../') ? source.delete_prefix('../') : "mingw-w64-crt/#{source}"
  url = "https://raw.githubusercontent.com/mingw-w64/mingw-w64/#{MINGW}/#{upstream}"
  retain("mingw14/#{name}", fetch(url), { 'kind' => 'upstream producer source/import definition; not a measured native export table',
                                         'issuer' => 'MinGW-w64', 'revision' => MINGW, 'release' => 'v14.0.0',
                                         'source_url' => url, 'normalization' => 'None',
                                         'license' => 'Input notice plus ../crt-initializers/mingw14/COPYING and DISCLAIMER.PD retained' })
end

names = 'exit|_exit|_Exit|_cexit|_c_exit|atexit|_crt_atexit|_onexit|onexit|quick_exit|at_quick_exit|_crt_at_quick_exit|_register_thread_local_exe_atexit_callback'
%w[x86 x64 arm64].each do |arch|
  member = "c/Redist/10.0.26100.0/ucrt/DLLs/#{arch}/ucrtbase.dll"
  entry = entries.fetch(member)
  bytes = sdk_member(entry)
  argv = ["#{LLVM}/llvm-readobj", '--coff-exports', '-']
  observation, status = Open3.capture2(*argv, stdin_data: bytes)
  raise "SDK export observation failed #{arch}" unless status.success?
  pattern = "^  Name: (#{names})$"
  observation = observation.lines.select { |line| line.match?(Regexp.new(pattern)) }.join
  raise "empty SDK exports #{arch}" if observation.empty?
  retain("symbols/microsoft-ucrtbase-#{arch}.txt", observation, {
    'kind' => 'publisher redistributable DLL export observation; genuine named exports but no native execution',
    'issuer' => 'Microsoft Corporation', 'revision' => 'Windows SDK 10.0.26100.0, package 10.0.26100.1',
    'input_sha256' => Digest::SHA256.hexdigest(bytes), 'input_bytes' => bytes.bytesize,
    'command_argv' => argv, 'command_stdin_sdk_member' => entry, 'selection_regex' => pattern,
    'binary_retention' => 'None; remote publisher ZIP member streamed to observer; member CRC and input SHA-256 retained' })
end
%w[x86 x64].each do |arch|
  tuple = arch == 'x86' ? ['i686', 'i686-w64-mingw32'] : ['x86_64', 'x86_64-w64-mingw32']
  %w[msvcrt-os ucrtbase].each do |runtime|
    input = "#{PKG}/toolchain-#{tuple[0]}/#{tuple[1]}/lib/lib#{runtime}.a"
    prefix = arch == 'x86' ? '_' : ''
    pattern = "( I __imp_| T | D __imp_)(#{prefix}(#{names}))$"
    observe("symbols/#{runtime}-#{arch}.txt", ["#{LLVM}/llvm-nm", '-A', '-g', input], {
      'kind' => 'installed archive symbol observation; not a native DLL export oracle',
      'issuer' => 'MinGW-w64', 'revision' => 'Homebrew MinGW-w64 14.0.0_3',
      'interpretation' => 'I __imp_ is import member; T implementation plus D __imp_ is a local shim and does not prove native named IAT availability'
    }, input, pattern)
  end
end

{
  'producer/gcc-x86-atexit.txt' => ["#{PKG}/toolchain-i686/i686-w64-mingw32/lib/crt2.o", '_atexit'],
  'producer/gcc-x64-atexit.txt' => ["#{PKG}/toolchain-x86_64/x86_64-w64-mingw32/lib/crt2.o", 'atexit'],
  'producer/zig-arm64-atexit.txt' => ['/Users/int/.cache/zig/o/152791cf652f60c4402bea4673565078/crt2.obj', 'atexit'],
  'producer/zig-arm64-tls-callback.txt' => ['/Users/int/.cache/zig/o/618f749787b034ac069f4c2294bef143/tls_atexit.obj', 'tls_callback']
}.each do |path, (input, symbol)|
  observe(path, ["#{LLVM}/llvm-objdump", '-dr', "--disassemble-symbols=#{symbol}", input], {
    'kind' => 'exact installed producer instruction/relocation observation; not executed native Windows behavior',
    'issuer' => path.include?('gcc-') ? 'Installed MinGW-w64 GCC' : 'Local Zig producer cache',
    'revision' => path.include?('gcc-') ? 'Homebrew MinGW-w64 14.0.0_3; GCC 16.2.0' : 'Cached object upstream producer invocation/source revision unknown; exact bytes hashed',
    'interpretation' => 'Calls and tail branches are observed in existing producer objects, not inferred only from undefined-symbol lists'
  }, input)
end

tools = ["#{LLVM}/llvm-nm", "#{LLVM}/llvm-readobj", "#{LLVM}/llvm-objdump", '/usr/bin/curl', '/usr/bin/ruby'].map do |path|
  argv = [path, '--version']
  output, status = Open3.capture2(*argv)
  raise "tool version failed #{path}" unless status.success?
  { 'path' => path, 'version' => output.strip, 'sha256' => Digest::SHA256.file(path).hexdigest }
end
manifest = { 'schema' => 1, 'retrieved' => DATE, 'baseline_head' => BASELINE,
             'purpose' => 'Global CRT termination/prototype/export and genuine producer evidence; no native Windows execution oracle',
             'microsoft_sdk_package' => package_metadata, 'tools' => tools,
             'microsoft_sdk_full_package_digest' => package_digest,
             'acquisition_script_sha256' => Digest::SHA256.file(__FILE__).hexdigest,
             'sources' => SOURCES }
File.binwrite(File.join(ROOT, 'sources.json'), JSON.pretty_generate(manifest) + "\n")
puts "retained #{SOURCES.length} references, #{SOURCES.sum { |source| source.fetch('bytes') }} bytes including reused archives"
puts "Publisher SDK source inspection directory (not repository vendoring): #{inspection_dir}"
