#!/usr/bin/env ruby
# Retain public inputs and exact metadata/observations; SDK bytes stay temporary.
require 'json'
require 'digest'
require 'open3'
require 'fileutils'
require 'tmpdir'

BOOT_ROOT = File.expand_path(__dir__)
BOOT_DATE = '2026-09-27'
BOOT_BASELINE = '9bc8ccdca85a5b0c9c74a7c446c85194efdc780d'
BOOT_CPP_REV = 'f2355df9f7136d8a2097193fc507882a7caeb5f5'
BOOT_HELPER_SHA = '09300dada01d906063cd04372c85d1249464283189039f23d342a066ee672a6d'
BOOT_PARENT_SHA = '8eb3cf9b4cc47d6ab65a6f3f436ea9558ff556e01a6a2850ba7592b32c82af8c'
BOOT_SEED_SHA = 'c374dde35736cfc237239d4a712910e6184c3b18236ebe234781f573cd11c85d'
BOOT_LLVM = '/Users/int/local/bin'
BOOT_ZIG = '/opt/homebrew/Cellar/zig/0.16.0_1/lib/zig/libc/mingw'
BOOT_PKG = '/opt/homebrew/Cellar/mingw-w64/14.0.0_3'
BOOT_NAMES = %w[_set_app_type _query_app_type _configthreadlocale __setusermatherr _fpreset __pxcptinfoptrs].freeze
BOOT_ABSENT = %w[__set_app_type _matherr].freeze
BOOT_PUBLIC = {
  'internal-set-app-type.md' => 'docs/c-runtime-library/internal-set-app-type.md',
  'setusermatherr.md' => 'docs/c-runtime-library/setusermatherr.md',
  'configthreadlocale.md' => 'docs/c-runtime-library/reference/configthreadlocale.md',
  'fpreset.md' => 'docs/c-runtime-library/reference/fpreset.md',
  'matherr.md' => 'docs/c-runtime-library/reference/matherr.md'
}.freeze
BOOT_REUSE = {
  'crt-initializers' => %w[microsoft/LICENSE microsoft/LICENSE-CODE microsoft/internal-crt-globals-and-functions.md
    mingw14/COPYING mingw14/DISCLAIMER.PD mingw14/msvcrt.def.in mingw14/func.def.in mingw14/crtexe.c
    zig/COPYING zig/crtexe.c],
  'crt-startup' => %w[microsoft/global-state.md zig/ucrtbase-common.def.in zig/api-ms-win-crt-runtime-l1-1-0.def.in],
  'crt-foundation' => %w[allocation/parameter-validation.md],
  'crt-stdio' => %w[producer/ordinary-x86-main-imports.txt producer/ordinary-x86-wmain-imports.txt
    producer/ordinary-x64-main-imports.txt producer/ordinary-x64-wmain-imports.txt
    producer/ordinary-arm64-main-imports.txt producer/ordinary-arm64-wmain-imports.txt]
}.freeze
BOOT_RANGES = {
  'x86' => {
    'set_app_type' => [0x10085990, 0x1008599f], 'query_app_type' => [0x1008cf90, 0x1008cf96],
    'configthreadlocale' => [0x10081eb0, 0x10081f12], 'pxcptinfoptrs' => [0x100887b0, 0x100887b9],
    'setusermatherr' => [0x100cc920, 0x100cc94d], 'math_state_index' => [0x10027590, 0x10027680],
    'fpreset' => [0x10058180, 0x100581ba], 'fpreset_precision' => [0x10099713, 0x10099734],
    'fpreset_getptd' => [0x100270f0, 0x10027110], 'fpreset_getptd_noexit' => [0x10027494, 0x10027590],
    'controlfp_s' => [0x10058030, 0x10058091], 'control87' => [0x10056ef0, 0x10057389],
    'fpreset_mxcsr' => [0x10057389, 0x1005740a], 'x87_control_convert' => [0x10057410, 0x100574f3]
  },
  'x64' => {
    'set_app_type' => [0x180085100, 0x180085107], 'query_app_type' => [0x1800a6d30, 0x1800a6d37],
    'configthreadlocale' => [0x1800843f0, 0x18008445b], 'pxcptinfoptrs' => [0x1800c1790, 0x1800c17a2],
    'getptd' => [0x1800128e0, 0x180012905],
    'setusermatherr' => [0x1800cfab0, 0x1800cfae8], 'math_state_index' => [0x1800125ac, 0x180012617],
    'fpreset' => [0x18008ac80, 0x18008ac8f]
  },
  'arm64' => {
    'set_app_type' => [0x180021110, 0x18002111c], 'query_app_type' => [0x180077b70, 0x180077b7c],
    'configthreadlocale' => [0x180026e70, 0x180026ef0], 'configthreadlocale_cold' => [0x1800cef80, 0x1800cefa0],
    'pxcptinfoptrs' => [0x18007ae40, 0x18007ae60], 'getptd' => [0x180020e70, 0x180020ed0],
    'setusermatherr' => [0x18009d7f0, 0x18009d838], 'math_state_index' => [0x18001fb60, 0x18001fbd0],
    'fpreset' => [0x180153800, 0x180153810]
  }
}.freeze

helper_path = File.expand_path('../crt-termination/acquire.rb', BOOT_ROOT)
raise 'changed SDK extraction helper' unless Digest::SHA256.file(helper_path).hexdigest == BOOT_HELPER_SHA
# Load only already-reviewed functions. Never evaluate the parent driver.
eval(File.read(helper_path).split("\nif ARGV == ").first, TOPLEVEL_BINDING, helper_path)
parent_path = File.expand_path('../crt-termination/sources.json', BOOT_ROOT)
raise 'changed SDK parent receipt' unless Digest::SHA256.file(parent_path).hexdigest == BOOT_PARENT_SHA
BOOT_PARENT = JSON.parse(File.binread(parent_path))
seed_path = File.join(BOOT_ROOT, 'sdk-inputs.json')
raise 'changed inspection seed' unless Digest::SHA256.file(seed_path).hexdigest == BOOT_SEED_SHA
BOOT_SEED = JSON.parse(File.binread(seed_path))

def boot_checked(bytes, entry)
  raise "changed bytes #{entry['path'] || entry['reference_id']}" unless bytes.bytesize == entry.fetch('bytes') && Digest::SHA256.hexdigest(bytes) == entry.fetch('sha256')
  bytes
end

def boot_write(path, bytes)
  raise 'write escaped owned archive' if path.start_with?('/') || path.split('/').include?('..')
  absolute = File.join(BOOT_ROOT, path)
  FileUtils.mkdir_p(File.dirname(absolute))
  File.binwrite(absolute, bytes)
end

def boot_record(path, bytes, metadata)
  boot_write(path, bytes)
  metadata.merge('path' => path, 'bytes' => bytes.bytesize, 'sha256' => Digest::SHA256.hexdigest(bytes), 'retrieved' => BOOT_DATE)
end

def boot_exports(bytes)
  command = ["#{BOOT_LLVM}/llvm-readobj", '--file-headers', '--coff-exports', '-']
  output, status = Open3.capture2(*command, stdin_data: bytes)
  raise 'publisher EAT observer failed' unless status.success?
  records = []
  record = nil
  table = 'native'
  output.each_line do |line|
    text = line.strip
    if text == 'HybridObject {'
      table = 'hybrid ARM64EC'
    elsif text == 'Export {'
      record = { 'table' => table }
    elsif record && text == '}'
      records << record if (BOOT_NAMES + BOOT_ABSENT).include?(record['Name'])
      record = nil
    elsif record && text =~ /^(Ordinal|Name|RVA): (.*)$/
      record[$1] = $2
    end
  end
  raise 'missing genuine publisher export' unless BOOT_NAMES.all? { |name| records.any? { |entry| entry['Name'] == name } }
  raise 'changed selected absent publisher names' if records.any? { |entry| BOOT_ABSENT.include?(entry['Name']) }
  data = { 'command_argv' => command, 'input_sha256' => Digest::SHA256.hexdigest(bytes), 'input_bytes' => bytes.bytesize,
           'full_output_sha256' => Digest::SHA256.hexdigest(output), 'selected_exports' => records,
           'header_identity_lines' => output.lines.grep(/^\s*(?:Format|Arch|AddressSize|Machine):/).map(&:strip),
           'selected_absent_names' => BOOT_ABSENT,
           'interpretation' => 'Genuine names in these exact publisher DLLs, not Windows execution. ARM64X includes a secondary ARM64EC EAT; the first/native RVAs are used for AArch64 disassembly.' }
  [JSON.pretty_generate(data) + "\n", command]
end

def boot_disassemble(bytes, arch)
  spans = BOOT_RANGES.fetch(arch).map do |label, (first, last)|
    command = ["#{BOOT_LLVM}/llvm-objdump", '--disassemble', "--start-address=0x#{first.to_s(16)}", "--stop-address=0x#{last.to_s(16)}", '--print-imm-hex', '-']
    output, status = Open3.capture2(*command, stdin_data: bytes)
    raise 'publisher disassembler failed' unless status.success?
    raise 'empty publisher disassembly' unless output.include?('Disassembly of section .text:')
    { 'label' => label, 'command_argv' => command, 'start_address' => first, 'stop_address_exclusive' => last,
      'output_sha256' => Digest::SHA256.hexdigest(output), 'output' => output }
  end
  JSON.pretty_generate('arch' => arch, 'input_sha256' => Digest::SHA256.hexdigest(bytes), 'input_bytes' => bytes.bytesize,
                       'image_base' => arch == 'x86' ? 0x10000000 : 0x180000000,
                       'interpretation' => 'Static publisher function/dependent-helper observation only. Nearest-export labels on unexported helpers are disassembler annotations, not genuine helper symbol identities. No proprietary DLL bytes retained.',
                       'spans' => spans) + "\n"
end

def boot_survey(entries)
  prefix = 'c/Source/10.0.26100.0/ucrt/'
  names = entries.keys.select { |name| name.start_with?(prefix) }.sort
  JSON.pretty_generate('sdk_source_member_count' => names.length,
                       'source_subdirectories' => names.map { |name| name.delete_prefix(prefix).split('/').first }.uniq.sort,
                       'math_directory_members' => names.select { |name| name.start_with?(prefix + 'math/') },
                       'fpreset_matherr_name_matches' => names.select { |name| name.match?(/fpreset|matherr/i) },
                       'internal_shared_header_name_matches' => entries.keys.select { |name| name.match?(/(?:^|\/)internal_shared\.h$/i) }.sort,
                       'interpretation' => 'ZIP member-name survey, not a proof that no mathematical implementation exists under unrelated names. No recovered Microsoft math source is claimed.') + "\n"
end

def boot_reuse(archive, path, manifest_name = 'sources.json')
  manifest_path = File.expand_path("../#{archive}/#{manifest_name}", BOOT_ROOT)
  prior = JSON.parse(File.binread(manifest_path))
  entry = prior.fetch('sources').find { |source| source['path'] == path }
  raise "missing reused source #{archive}/#{path}" unless entry
  relative = "../#{archive}/#{path}"
  bytes = File.binread(File.join(BOOT_ROOT, relative))
  raise 'changed reused input' unless Digest::SHA256.hexdigest(bytes) == entry.fetch('sha256') && (!entry['bytes'] || bytes.bytesize == entry['bytes'])
  entry.merge('path' => relative, 'bytes' => bytes.bytesize, 'reuse_path' => path,
              'reuse_manifest' => "../#{archive}/#{manifest_name}", 'reuse_manifest_sha256' => Digest::SHA256.file(manifest_path).hexdigest,
              'license_paths' => Array(entry['license_paths']).map { |license| "../#{archive}/#{license}" })
end

def boot_verify(network)
  manifest = JSON.parse(File.binread(File.join(BOOT_ROOT, 'sources.json')))
  raise 'changed acquisition script' unless Digest::SHA256.file(__FILE__).hexdigest == manifest.fetch('acquisition_script_sha256')
  counts = { 'retained_hash_size_checks' => 0, 'sdk_metadata_receipts' => 0, 'installed_input_hashes' => 0,
             'copy_replays' => 0, 'command_replays' => 0, 'network_source_replays' => 0, 'publisher_observation_replays' => 0,
             'tool_hash_checks' => 0, 'unavailable_inputs_or_tools' => [], 'raw_sdk_bytes_committed' => false,
             'native_windows_execution_oracle' => 'unknown', 'nuget_signature_verified' => false }
  entries = nil
  if network
    entries, metadata = sdk_directory
    raise 'changed SDK directory' unless metadata == manifest.fetch('microsoft_sdk_package')
  end
  sdk_cache = {}
  installed = {}
  manifest.fetch('tools').each do |tool|
    if File.file?(tool.fetch('path'))
      raise 'changed tool' unless Digest::SHA256.file(tool.fetch('path')).hexdigest == tool.fetch('sha256')
      counts['tool_hash_checks'] += 1
    else
      counts['unavailable_inputs_or_tools'] << tool.fetch('path')
    end
  end
  manifest.fetch('sources').each do |entry|
    retained = entry['path'] && boot_checked(File.binread(File.join(BOOT_ROOT, entry['path'])), entry)
    counts[entry['path'] ? 'retained_hash_size_checks' : 'sdk_metadata_receipts'] += 1
    if entry['reuse_manifest']
      path = File.join(BOOT_ROOT, entry.fetch('reuse_manifest'))
      raise 'changed reused manifest' unless Digest::SHA256.file(path).hexdigest == entry.fetch('reuse_manifest_sha256')
      old = JSON.parse(File.binread(path)).fetch('sources').find { |source| entry['reuse_path'] ? source['path'] == entry['reuse_path'] : source['reference_id'] == entry['reference_id'] }
      raise 'changed reused metadata' unless old && old.fetch('sha256') == entry.fetch('sha256')
    end
    if entry['input_path']
      path = entry.fetch('input_path')
      if File.file?(path)
        bytes = File.binread(path)
        raise 'changed installed input' unless (!entry['input_bytes'] || bytes.bytesize == entry['input_bytes']) && Digest::SHA256.hexdigest(bytes) == entry.fetch('input_sha256')
        installed[path] = true
        if entry['copy_installed_bytes']
          raise 'changed installed copy' unless bytes == retained
          counts['copy_replays'] += 1
        elsif entry['command_argv'] && File.file?(entry['command_argv'].first)
          actual, status = entry['stdin_source'] == 'input_path' ? Open3.capture2(*entry['command_argv'], stdin_data: bytes) : Open3.capture2(*entry['command_argv'])
          raise 'installed command failed' unless status.success?
          pattern = entry['selection_regex']
          actual = actual.lines.select { |line| line.match?(Regexp.new(pattern)) }.join if pattern
          raise 'changed installed observation' unless actual == retained
          counts['command_replays'] += 1
        end
      else
        counts['unavailable_inputs_or_tools'] << path
      end
    end
    next unless network
    if entry['sdk_zip_member']
      member = entry.fetch('sdk_zip_member')
      raise 'changed SDK ZIP metadata' unless entries.fetch(member.fetch('member')) == member
      actual = sdk_cache[member.fetch('member')] ||= sdk_member(member)
      boot_checked(actual, entry)
      counts['network_source_replays'] += 1
    elsif entry['publisher_arch']
      id = "microsoft-sdk/ucrtbase-#{entry.fetch('publisher_arch')}.dll"
      source = manifest.fetch('sources').find { |item| item['reference_id'] == id }
      member = source.fetch('sdk_zip_member')
      bytes = sdk_cache[member.fetch('member')] ||= sdk_member(member)
      boot_checked(bytes, source)
      actual = entry.fetch('publisher_observation') == 'exports' ? boot_exports(bytes).first : boot_disassemble(bytes, entry.fetch('publisher_arch'))
      raise 'changed publisher observation' unless actual == retained
      counts['publisher_observation_replays'] += 1
    elsif entry['sdk_member_survey']
      raise 'changed member survey' unless boot_survey(entries) == retained
      counts['publisher_observation_replays'] += 1
    elsif entry['source_url'] && !entry['input_path'] && !entry['local_seed']
      actual = fetch(entry.fetch('source_url'))
      boot_checked(actual, entry)
      counts['network_source_replays'] += 1
    end
  end
  counts['installed_input_hashes'] = installed.length
  counts['unavailable_inputs_or_tools'].uniq!
  raise 'changed full package receipt' unless manifest.fetch('microsoft_sdk_full_package_digest').reject { |key, _| key == 'reuse_manifest' } == BOOT_PARENT.fetch('microsoft_sdk_full_package_digest')
  counts
end

if ARGV == ['--verify'] || ARGV == ['--verify-network']
  puts JSON.pretty_generate(boot_verify(ARGV == ['--verify-network']))
  exit
elsif !ARGV.empty?
  abort 'usage: acquire.rb [--verify|--verify-network]'
end

sources = []
{
  '../../x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf' => {
    'sha256' => '6f6286056edad4ffdca8716e9039e9598e9e71ab029284facde6a786e1b65f73',
    'bytes' => 26_149_105, 'kind' => 'reused unmodified primary architecture manual',
    'issuer' => 'Intel Corporation', 'revision' => '086, December 2024; order 253665-086US',
    'canonical_url' => 'https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html',
    'original_download_url' => 'unknown', 'original_retrieval_date' => 'unknown',
    'sections' => ['Vol. 1 1.3.2', 'Vol. 1 8.1.5 and Figure 8-6', 'Vol. 2A FINIT/FNINIT', 'Vol. 2A FLDCW'],
    'license' => 'Existing unmodified PDF retains publisher notices; see accompanying provenance receipt'
  },
  '../../x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.provenance.md' => {
    'sha256' => '8ba0b61c0d533af2b26b59f2b4756909b0be6465f4cba29a434b77cf013f8e6b',
    'bytes' => 1_497, 'kind' => 'reused architecture-manual provenance receipt',
    'issuer' => 'Repository provenance inspection', 'revision' => '2026-09-08'
  }
}.each do |path, metadata|
  bytes = boot_checked(File.binread(File.join(BOOT_ROOT, path)), metadata)
  sources << metadata.merge('path' => path, 'reused_existing_archive' => true, 'local_seed' => true)
end
BOOT_REUSE.each do |archive, paths|
  manifest_name = archive == 'crt-foundation' ? 'manifest-alloc.json' : 'sources.json'
  paths.each { |path| sources << boot_reuse(archive, path, manifest_name) }
end
BOOT_PUBLIC.each do |name, relative|
  url = "https://raw.githubusercontent.com/MicrosoftDocs/cpp-docs/#{BOOT_CPP_REV}/#{relative}"
  bytes = fetch(url)
  canonical = relative.delete_prefix('docs/').delete_suffix('.md')
  sources << boot_record("microsoft/#{name}", bytes, {
    'kind' => 'publisher public documentation', 'issuer' => 'MicrosoftDocs', 'revision' => BOOT_CPP_REV,
    'source_url' => url, 'canonical_url' => "https://learn.microsoft.com/en-us/cpp/#{canonical}?view=msvc-170",
    'normalization' => 'None; exact raw Markdown bytes', 'license' => 'CC-BY-4.0 prose; MIT samples; exact reused owning licenses retained'
  })
end
entries, metadata = sdk_directory
raise 'changed SDK metadata' unless metadata == BOOT_PARENT.fetch('microsoft_sdk_package')
inspection = Dir.mktmpdir('rax-crt-bootstrap-sdk.')
sdk = {}
BOOT_SEED.each do |seed|
  member = entries.fetch(seed.fetch('sdk_zip_member').fetch('member'))
  raise 'changed inspected member metadata' unless member == seed.fetch('sdk_zip_member')
  bytes = boot_checked(sdk_member(member), seed)
  sdk[member.fetch('member')] = bytes
  File.binwrite(File.join(inspection, File.basename(seed.fetch('reference_id'))), bytes)
  sources << seed.merge('kind' => 'publisher SDK source/header/DLL metadata receipt; raw bytes excluded',
                        'issuer' => 'Microsoft Corporation', 'revision' => 'SDK 10.0.26100.0; package 10.0.26100.1',
                        'source_url' => SDK_URL, 'retrieved' => BOOT_DATE, 'normalization' => 'None; uncompressed ZIP bytes',
                        'retention' => 'Temporary inspection only; raw proprietary source, header, license and DLL bytes excluded from repository',
                        'license' => 'Publisher copyright; source redistribution authorization unknown; metadata retained only')
end
[['crt-termination', %w[corecrt_internal.h per_thread_data.cpp package.nuspec sdk_license.rtf]], ['crt-exit', %w[signal.h]]].each do |archive, names|
  manifest_path = File.expand_path("../#{archive}/sources.json", BOOT_ROOT)
  prior = JSON.parse(File.binread(manifest_path))
  names.each do |name|
    entry = prior.fetch('sources').find { |item| item['reference_id'] == "microsoft-sdk/#{name}" }
    raise 'missing reused SDK receipt' unless entry
    sources << entry.merge('reuse_manifest' => "../#{archive}/sources.json", 'reuse_manifest_sha256' => Digest::SHA256.file(manifest_path).hexdigest)
  end
end
%w[x86 x64 arm64].each do |arch|
  member = "c/Redist/10.0.26100.0/ucrt/DLLs/#{arch}/ucrtbase.dll"
  bytes = sdk.fetch(member)
  output, = boot_exports(bytes)
  sources << boot_record("publisher/ucrtbase-#{arch}-exports.json", output, { 'kind' => 'publisher EAT observation',
    'publisher_arch' => arch, 'publisher_observation' => 'exports', 'input_sha256' => Digest::SHA256.hexdigest(bytes), 'source_url' => SDK_URL })
  sources << boot_record("publisher/ucrtbase-#{arch}-disassembly.json", boot_disassemble(bytes, arch), {
    'kind' => 'scoped static publisher instruction observation, not native execution', 'publisher_arch' => arch,
    'publisher_observation' => 'disassembly', 'input_sha256' => Digest::SHA256.hexdigest(bytes), 'source_url' => SDK_URL })
end
sources << boot_record('publisher/member-survey.json', boot_survey(entries), { 'kind' => 'ZIP member-name survey', 'sdk_member_survey' => true, 'source_url' => SDK_URL })
{
  'api-ms-win-crt-locale-l1-1-0.def' => 'lib-common/api-ms-win-crt-locale-l1-1-0.def',
  'api-ms-win-crt-math-l1-1-0.def.in' => 'lib-common/api-ms-win-crt-math-l1-1-0.def.in',
  'usermatherr.c' => 'crt/usermatherr.c', 'CRT_fp10.c' => 'crt/CRT_fp10.c', 'fesetenv.c' => 'misc/fesetenv.c'
}.each do |name, relative|
  input = File.join(BOOT_ZIG, relative)
  bytes = File.binread(input)
  sources << boot_record("zig/#{name}", bytes, { 'kind' => 'installed producer source/import definition; not Microsoft DLL implementation',
    'issuer' => 'MinGW-w64 bundled with Zig', 'revision' => 'Zig 0.16.0 Homebrew 0.16.0_1; exact bundled MinGW commit unknown',
    'input_path' => input, 'input_sha256' => Digest::SHA256.hexdigest(bytes), 'input_bytes' => bytes.bytesize,
    'copy_installed_bytes' => true, 'normalization' => 'None', 'license' => 'Input notice and reused MinGW/Zig owning licenses retained' })
end
%w[x86 x64].each do |arch|
  tuple = arch == 'x86' ? %w[i686 i686-w64-mingw32] : %w[x86_64 x86_64-w64-mingw32]
  %w[msvcrt-os ucrtbase].each do |runtime|
    input = "#{BOOT_PKG}/toolchain-#{tuple[0]}/#{tuple[1]}/lib/lib#{runtime}.a"
    prefix = arch == 'x86' ? '_' : ''
    pattern = "( I __imp_| T | D __imp_)(#{prefix}(#{(BOOT_NAMES + BOOT_ABSENT).join('|')}))$"
    command = ["#{BOOT_LLVM}/llvm-nm", '-A', '-g', input]
    output, status = Open3.capture2(*command)
    raise 'import inventory failed' unless status.success?
    output = output.lines.select { |line| line.match?(Regexp.new(pattern)) }.join
    raise 'empty import inventory' if output.empty?
    sources << boot_record("symbols/#{runtime}-#{arch}.txt", output, { 'kind' => 'installed import/archive observation; not native Windows inventory',
      'issuer' => 'MinGW-w64', 'revision' => 'Homebrew MinGW-w64 14.0.0_3', 'input_path' => input,
      'input_sha256' => Digest::SHA256.file(input).hexdigest, 'input_bytes' => File.size(input), 'command_argv' => command,
      'selection_regex' => pattern, 'interpretation' => 'I __imp_ proves an import object; T+D compatibility members are local shims. DEF aliases and actual PE names establish the imported spelling.' })
  end
end
seed_bytes = File.binread(seed_path)
sources << { 'path' => 'sdk-inputs.json', 'kind' => 'metadata-only seed of the exact 16 inspected SDK inputs',
             'local_seed' => true, 'sha256' => Digest::SHA256.hexdigest(seed_bytes), 'bytes' => seed_bytes.bytesize, 'retrieved' => BOOT_DATE }
tools = ["#{BOOT_LLVM}/llvm-readobj", "#{BOOT_LLVM}/llvm-objdump", "#{BOOT_LLVM}/llvm-nm", '/usr/bin/curl', '/usr/bin/ruby'].map do |path|
  version, status = Open3.capture2(path, '--version')
  raise 'tool version failed' unless status.success?
  { 'path' => path, 'sha256' => Digest::SHA256.file(path).hexdigest, 'version' => version.strip }
end
manifest = { 'schema' => 1, 'retrieved' => BOOT_DATE, 'baseline_head' => BOOT_BASELINE,
             'purpose' => 'CRT bootstrap primary contracts, opaque state/accessor and architectural reset evidence; no implementation or native execution claim',
             'microsoft_sdk_package' => metadata,
             'microsoft_sdk_full_package_digest' => BOOT_PARENT.fetch('microsoft_sdk_full_package_digest').merge('reuse_manifest' => '../crt-termination/sources.json'),
             'sdk_helper_sha256' => BOOT_HELPER_SHA, 'sdk_parent_manifest_sha256' => BOOT_PARENT_SHA,
             'raw_sdk_bytes_committed' => false, 'nuget_signature_verification' => 'not performed',
             'native_windows_execution_oracle' => 'unknown', 'acquisition_script_sha256' => Digest::SHA256.file(__FILE__).hexdigest,
             'tools' => tools, 'sources' => sources }
boot_write('sources.json', JSON.pretty_generate(manifest) + "\n")
puts JSON.pretty_generate('sources' => sources.length, 'inspection_directory' => inspection,
                          'manifest_sha256' => Digest::SHA256.file(File.join(BOOT_ROOT, 'sources.json')).hexdigest,
                          'raw_sdk_bytes_committed' => false)
