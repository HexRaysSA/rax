#!/usr/bin/env ruby
# Byte-preserving evidence acquisition; no runtime, guest fixture, or CRT build.
require 'digest'
require 'fileutils'
require 'json'
require 'open3'

ROOT = File.expand_path(__dir__)
DATE = '2026-09-27'
BASELINE = '9b73397628567e675f129ecf38896ee50f601576'
CPP = 'f2355df9f7136d8a2097193fc507882a7caeb5f5'
MINGW = '9b3dd0125792fe94d16cacdc596dbd42fca1b369'
PKG = '/opt/homebrew/Cellar/mingw-w64/14.0.0_3'
ZIG = '/opt/homebrew/Cellar/zig/0.16.0_1/lib/zig/libc'
LLVM = '/Users/int/local/bin'
ENTRIES = []

if ARGV == ['--verify']
  manifest = JSON.parse(File.binread(File.join(ROOT, 'sources.json')))
  hashes = 0
  inputs = {}
  extracts = 0
  replays = 0
  unavailable = []
  manifest.fetch('sources').each do |entry|
    output = File.binread(File.join(ROOT, entry.fetch('path')))
    raise "changed retained bytes: #{entry['path']}" unless
      Digest::SHA256.hexdigest(output) == entry.fetch('sha256') && output.bytesize == entry.fetch('bytes')
    hashes += 1
    input = entry['input_path']
    next unless input
    unless File.file?(input)
      unavailable << input
      next
    end
    bytes = File.binread(input)
    raise "changed installed producer: #{input}" unless Digest::SHA256.hexdigest(bytes) == entry.fetch('input_sha256')
    inputs[input] = true
    recipe = entry['extraction_command']
    ranges = entry['line_ranges_1based_inclusive']
    if !ranges && recipe && recipe.start_with?("sed -n '")
      commands = recipe.split("'")[1].split(';')
      ranges = commands.map do |command|
        raise "unsupported extraction #{command}" unless command.match?(/\A\d+(?:,\d+)?p\z/)
        first, last = command.delete('p').split(',').map(&:to_i)
        [first, last || first]
      end
    end
    if ranges
      expected = ranges.flat_map { |first, last| (first..last).map { |line| bytes.lines.fetch(line - 1) } }.join
      raise "changed extraction: #{entry['path']}" unless expected == output
      extracts += 1
    elsif recipe && recipe.start_with?('complete byte copy')
      raise "changed full copy: #{entry['path']}" unless bytes == output
      extracts += 1
    end
    argv = entry['command_argv']
    next unless argv
    required = [argv.first, entry['producer_argv'] && entry['producer_argv'].first].compact
    unless required.all? { |tool| File.file?(tool) }
      unavailable.concat(required.reject { |tool| File.file?(tool) })
      next
    end
    stdin = entry['stdin_source'] == 'input_path' ? bytes : nil
    if entry['producer_argv']
      stdin, status = Open3.capture2(*entry.fetch('producer_argv'))
      raise "member extraction failed: #{entry['path']}" unless status.success?
      raise "changed member: #{entry['path']}" unless Digest::SHA256.hexdigest(stdin) == entry.fetch('member_sha256')
    end
    options = stdin ? { stdin_data: stdin } : {}
    actual, status = if entry['observation_stream'] == 'combined stdout/stderr'
                       Open3.capture2e(*argv, **options)
                     else
                       Open3.capture2(*argv, **options)
                     end
    raise "observation replay failed: #{entry['path']}" unless status.success?
    if entry['selection_regex']
      actual = actual.lines.select { |line| line.match?(Regexp.new(entry.fetch('selection_regex'))) }.join
    end
    raise "changed observation: #{entry['path']}" unless actual == output
    replays += 1
  end
  manifest.fetch('tools').each do |tool|
    unless File.file?(tool.fetch('path'))
      unavailable << tool.fetch('path')
      next
    end
    raise "changed tool: #{tool['path']}" unless Digest::SHA256.file(tool.fetch('path')).hexdigest == tool.fetch('sha256')
  end
  raise 'changed acquisition script' unless Digest::SHA256.file(__FILE__).hexdigest == manifest.fetch('acquisition_script_sha256')
  puts JSON.generate('retained_hash_size_checks' => hashes, 'available_installed_input_hashes' => inputs.length,
                     'exact_copy_or_extraction_replays' => extracts, 'derived_command_replays' => replays,
                     'unavailable_inputs_or_tools' => unavailable.uniq)
  exit
elsif !ARGV.empty?
  abort 'usage: acquire.rb [--verify]'
end

def record(path, metadata)
  bytes = File.binread(File.join(ROOT, path))
  if path.end_with?('.md')
    metadata = metadata.merge(
      'title' => bytes[/^title:\s*"?([^"\r\n]+)"?\r?$/, 1],
      'document_date' => bytes[/^ms\.date:\s*"?([^"\r\n]+)"?\r?$/, 1]
    )
  end
  ENTRIES << metadata.merge('path' => path, 'retrieved' => DATE,
                           'sha256' => Digest::SHA256.hexdigest(bytes), 'bytes' => bytes.bytesize)
end

def generated(path, bytes, metadata)
  absolute = File.join(ROOT, path)
  FileUtils.mkdir_p(File.dirname(absolute))
  File.binwrite(absolute, bytes)
  record(path, metadata)
end

def download(path, url, metadata)
  absolute = File.join(ROOT, path)
  FileUtils.mkdir_p(File.dirname(absolute))
  raise "download failed: #{url}" unless system(
    'curl', '--fail', '--silent', '--show-error', '--retry', '2',
    '--connect-timeout', '15', '--max-time', '60', url, '-o', absolute
  )
  record(path, metadata.merge('source_url' => url, 'normalization' => 'None'))
  puts "retained #{path}"
  $stdout.flush
end

def reuse(archive, paths, manifest_name = 'sources.json')
  manifest = File.join(ROOT, "../#{archive}/#{manifest_name}")
  prior = JSON.parse(File.binread(manifest))
  paths.each do |path|
    old = prior.fetch('sources').find { |entry| entry.fetch('path') == path }
    raise "missing retained source #{archive}/#{path}" unless old
    relative = "../#{archive}/#{path}"
    absolute = File.join(ROOT, relative)
    size = File.size(absolute)
    raise "retained source changed #{relative}" unless
      Digest::SHA256.file(absolute).hexdigest == old.fetch('sha256') &&
      (!old['bytes'] || size == old.fetch('bytes'))
    metadata = old.merge('path' => relative, 'bytes' => size,
                         'reuse_manifest' => "../#{archive}/#{manifest_name}")
    if old['license_paths']
      metadata['original_license_paths_in_reuse_manifest'] = old.fetch('license_paths')
      metadata['license_paths'] = old.fetch('license_paths').map do |license|
        license_input = File.join(ROOT, "../#{archive}/#{license}")
        digest = Digest::SHA256.file(license_input).hexdigest
        retained = ENTRIES.find { |entry| entry.fetch('sha256') == digest && entry.fetch('bytes') == File.size(license_input) }
        raise "license not already retained #{license_input}" unless retained
        retained.fetch('path')
      end
    end
    ENTRIES << metadata
  end
end

def installed(path, input, metadata, ranges = nil)
  bytes = File.binread(input)
  lines = ranges && ranges.flat_map { |first, last| (first..last).to_a }
  result = lines ? lines.map { |line| bytes.lines.fetch(line - 1) }.join : bytes
  recipe = lines ? "sed -n '#{ranges.map { |first, last| first == last ? "#{first}p" : "#{first},#{last}p" }.join(';')}' #{input}" : "complete byte copy of #{input}"
  generated(path, result, metadata.merge(
    'input_path' => input, 'input_sha256' => Digest::SHA256.hexdigest(bytes),
    'input_bytes' => bytes.bytesize, 'extraction_command' => recipe,
    'line_ranges_1based_inclusive' => ranges,
    'normalization' => 'None; complete input or exact line subsequence'
  ))
end

reuse('crt-initializers', %w[
  microsoft/LICENSE microsoft/LICENSE-CODE microsoft/internal-crt-globals-and-functions.md
  microsoft/exit-exit-exit.md microsoft/cexit-c-exit.md microsoft/atexit.md
  microsoft/onexit-onexit-m.md mingw14/msvcrt.def.in mingw14/func.def.in
  mingw14/COPYING mingw14/DISCLAIMER.PD mingw14/stdlib-startup-excerpt.h
  zig/COPYING zig/crtexe.c
])
reuse('crt-startup', %w[microsoft/global-state.md zig/ucrtbase-common.def.in])
reuse('crt-foundation', %w[allocation/parameter-validation.md], 'manifest-alloc.json')

cpp_root = "https://raw.githubusercontent.com/MicrosoftDocs/cpp-docs/#{CPP}/docs/c-runtime-library"
%w[p-fmode p-commode fmode stdin-stdout-stderr stream-i-o text-and-binary-mode-file-i-o].each do |page|
  download("microsoft/#{page}.md", "#{cpp_root}/#{page}.md", {
    'kind' => 'publisher documentation', 'issuer' => 'Microsoft', 'revision' => CPP,
    'canonical_url' => "https://learn.microsoft.com/en-us/cpp/c-runtime-library/#{page}?view=msvc-170",
    'license' => 'CC-BY-4.0 prose; MIT code samples; owning reused MicrosoftDocs licenses'
  })
end
%w[set-fmode get-fmode setvbuf fflush fread fwrite fclose-fcloseall feof ferror clearerr
   fileno open-osfhandle get-osfhandle fdopen-wfdopen close setmode read write fopen-wfopen].each do |page|
  download("microsoft/#{page}.md", "#{cpp_root}/reference/#{page}.md", {
    'kind' => 'publisher documentation', 'issuer' => 'Microsoft', 'revision' => CPP,
    'canonical_url' => "https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/#{page}?view=msvc-170",
    'license' => 'CC-BY-4.0 prose; MIT code samples; owning reused MicrosoftDocs licenses'
  })
end

download('mingw14/crt-aliases.def.in',
         "https://raw.githubusercontent.com/mingw-w64/mingw-w64/#{MINGW}/mingw-w64-crt/def-include/crt-aliases.def.in", {
  'kind' => 'upstream import aliases; not measured native DLL exports', 'issuer' => 'MinGW-w64',
  'revision' => MINGW, 'release' => 'v14.0.0',
  'license' => 'Input notices plus reused MinGW-w64 COPYING and DISCLAIMER.PD'
})

header_metadata = {
  'kind' => 'installed public header excerpt', 'issuer' => 'MinGW-w64',
  'revision' => 'Homebrew MinGW-w64 14.0.0_3; exact build commit unknown',
  'license' => 'Public Domain input notice; reused MinGW COPYING and DISCLAIMER.PD'
}
zig_metadata = {
  'kind' => 'installed public header excerpt', 'issuer' => 'MinGW-w64 bundled with Zig',
  'revision' => 'Zig 0.16.0 Homebrew 0.16.0_1; bundled MinGW exact upstream commit unknown',
  'license' => 'Input notices plus reused installed Zig-bundled MinGW COPYING'
}
%w[x86 x64].each do |arch|
  tuple = arch == 'x86' ? ['i686', 'i686-w64-mingw32'] : ['x86_64', 'x86_64-w64-mingw32']
  include_path = "#{PKG}/toolchain-#{tuple[0]}/#{tuple[1]}/include"
  installed("mingw14/stdio-#{arch}-excerpt.h", "#{include_path}/stdio.h", header_metadata,
            [[1, 144], [542, 558], [571, 571], [576, 576], [599, 599], [640, 640], [1164, 1165], [1206, 1216]])
end
installed('zig/stdio-excerpt.h', "#{ZIG}/include/any-windows-any/stdio.h", zig_metadata,
          [[1, 144], [542, 558], [571, 571], [576, 576], [622, 622], [660, 660], [1254, 1255], [1296, 1313]])
installed('mingw14/corecrt-packing-excerpt.h',
          "#{PKG}/toolchain-x86_64/x86_64-w64-mingw32/include/corecrt.h", header_metadata, [[1, 25]])
installed('mingw14/io-excerpt.h',
          "#{PKG}/toolchain-x86_64/x86_64-w64-mingw32/include/io.h", header_metadata,
          [[1, 8], [212, 212], [243, 243], [311, 312]])
installed('zig/io-excerpt.h', "#{ZIG}/include/any-windows-any/io.h", zig_metadata,
          [[1, 8], [200, 200], [231, 231], [338, 339]])
installed('mingw14/fcntl-excerpt.h',
          "#{PKG}/toolchain-x86_64/x86_64-w64-mingw32/include/fcntl.h", header_metadata, [[1, 52]])
installed('zig/internal-file-excerpt.h', "#{ZIG}/mingw/include/internal.h", zig_metadata.merge(
  'kind' => 'installed implementation header excerpt; not native UCRT internals'
), [[1, 5], [72, 95]])
%w[xtxtmode.c xncommod.c].each do |name|
  installed("zig/#{name}", "#{ZIG}/mingw/crt/#{name}", zig_metadata.merge(
    'kind' => 'installed compatibility startup implementation; not native Microsoft CRT oracle'
  ))
end
installed('zig/api-ms-win-crt-stdio.def',
          "#{ZIG}/mingw/lib-common/api-ms-win-crt-stdio-l1-1-0.def", zig_metadata.merge(
  'kind' => 'installed import definition; not measured native DLL exports'
))

names = '__p__fmode|__p__commode|__p__iob|__iob_func|__acrt_iob_func|_fmode|_commode|_iob|_get_fmode|_set_fmode|setvbuf|fflush|fread|fwrite|fclose|feof|ferror|clearerr|_fileno|_open_osfhandle|_get_osfhandle|_fdopen|_wfdopen|_close|_setmode|_read|_write|fopen|_wfopen'
%w[x86 x64].each do |arch|
  tuple = arch == 'x86' ? ['i686', 'i686-w64-mingw32'] : ['x86_64', 'x86_64-w64-mingw32']
  %w[msvcrt-os ucrtbase].each do |runtime|
    input = "#{PKG}/toolchain-#{tuple[0]}/#{tuple[1]}/lib/lib#{runtime}.a"
    prefix = arch == 'x86' ? '_' : ''
    pattern = "( I __imp_| T | D __imp_)(#{prefix}(#{names}))$"
    argv = ["#{LLVM}/llvm-nm", '-A', '-g', input]
    observation, status = Open3.capture2(*argv)
    raise "llvm-nm failed: #{input}" unless status.success?
    filtered = observation.lines.select { |line| line.match?(Regexp.new(pattern)) }.join
    raise "empty symbol observation: #{input}" if filtered.empty?
    generated("symbols/#{runtime}-#{arch}.txt", filtered, {
      'kind' => 'derived archive symbol observation; not native DLL export oracle',
      'issuer' => 'MinGW-w64', 'revision' => header_metadata['revision'],
      'input_path' => input, 'input_sha256' => Digest::SHA256.file(input).hexdigest,
      'command_argv' => argv, 'selection_regex' => pattern,
      'normalization' => 'Complete selected output lines; no text changes',
      'interpretation' => 'T plus D __imp_ is a local compatibility body. I __imp_ establishes an import member, but PE import spelling can differ through aliases; inspect .idata$6.'
    })
  end
end

members = [
  ['x86', 'i686', 'i686-w64-mingw32', 'libmsvcrt_defs00210.o', '__iob_func', '__p__iob'],
  ['x64', 'x86_64', 'x86_64-w64-mingw32', 'libmsvcrt_defs00132.o', '__p__iob', '__iob_func']
]
members.each do |arch, machine, tuple, member, c_name, import_name|
  archive = "#{PKG}/toolchain-#{machine}/#{tuple}/lib/libmsvcrt-os.a"
  producer = ["#{LLVM}/llvm-ar", 'p', archive, member]
  bytes, status = Open3.capture2(*producer)
  raise "archive member extraction failed: #{member}" unless status.success?
  argv = ["#{LLVM}/llvm-readobj", '--sections', '--section-data', '-']
  text, status = Open3.capture2(*argv, stdin_data: bytes)
  raise "llvm-readobj failed: #{member}" unless status.success?
  raise "missing expected import #{import_name}" unless text.include?(import_name)
  generated("symbols/msvcrt-iob-alias-#{arch}.txt", text, {
    'kind' => 'derived exact archive-member section observation; not native DLL export oracle',
    'issuer' => 'MinGW-w64', 'revision' => header_metadata['revision'],
    'input_path' => archive, 'input_sha256' => Digest::SHA256.file(archive).hexdigest,
    'member' => member, 'member_sha256' => Digest::SHA256.hexdigest(bytes),
    'producer_argv' => producer, 'command_argv' => argv, 'stdin' => 'exact extracted member bytes',
    'c_symbol_name' => c_name, 'pe_import_name' => import_name,
    'normalization' => 'None; complete llvm-readobj stdout'
  })
end
%w[x86 x64].each do |arch|
  tuple = arch == 'x86' ? ['i686', 'i686-w64-mingw32', 'lib32'] : ['x86_64', 'x86_64-w64-mingw32', 'lib64']
  archive = "#{PKG}/toolchain-#{tuple[0]}/#{tuple[1]}/lib/libmsvcrt-os.a"
  member = "#{tuple[2]}_libmsvcrt_common_a-acrt_iob_func.o"
  producer = ["#{LLVM}/llvm-ar", 'p', archive, member]
  bytes, status = Open3.capture2(*producer)
  raise "archive member extraction failed: #{member}" unless status.success?
  argv = ["#{LLVM}/llvm-objdump", '-dr', '-']
  text, status = Open3.capture2(*argv, stdin_data: bytes)
  raise "llvm-objdump failed: #{member}" unless status.success?
  generated("symbols/msvcrt-acrt-shim-#{arch}.txt", text, {
    'kind' => 'derived compatibility-body disassembly; not native Microsoft DLL implementation',
    'issuer' => 'MinGW-w64', 'revision' => header_metadata['revision'],
    'input_path' => archive, 'input_sha256' => Digest::SHA256.file(archive).hexdigest,
    'member' => member, 'member_sha256' => Digest::SHA256.hexdigest(bytes),
    'producer_argv' => producer, 'command_argv' => argv, 'stdin' => 'exact extracted member bytes',
    'normalization' => 'None; complete llvm-objdump stdout'
  })
end

gcc_paths = []
%w[x86 x64].each do |arch|
  tuple = arch == 'x86' ? ['i686', 'i686-w64-mingw32'] : ['x86_64', 'x86_64-w64-mingw32']
  base = "#{PKG}/toolchain-#{tuple[0]}"
  gcc = "#{base}/bin/#{tuple[1]}-gcc"
  gcc_paths << gcc
  %w[crt2.o crt2u.o].each do |name|
    input = "#{base}/#{tuple[1]}/lib/#{name}"
    argv = ["#{LLVM}/llvm-nm", '-u', input]
    text, status = Open3.capture2(*argv)
    raise "startup object observation failed: #{input}" unless status.success?
    generated("producer/gcc-#{arch}-#{name}.txt", text, {
      'kind' => 'derived undefined-symbol observation; not complete linked PE import graph',
      'issuer' => 'installed MinGW-w64 GCC', 'revision' => header_metadata['revision'],
      'input_path' => input, 'input_sha256' => Digest::SHA256.file(input).hexdigest,
      'input_bytes' => File.size(input), 'command_argv' => argv,
      'normalization' => 'None; complete llvm-nm stdout',
      'interpretation' => 'Undefined object symbols may resolve to local archive bodies or genuine IAT imports; final linked PE is a separate observation.'
    })
  end
  [false, true].each do |wide|
    argv = [gcc, '-###', '-save-temps=obj']
    argv << '-municode' if wide
    argv.concat(['-x', 'c', '/dev/null', '-o', '/dev/null'])
    text, status = Open3.capture2e(*argv)
    raise "GCC dry run failed: #{gcc}" unless status.success?
    generated("producer/gcc-#{arch}-#{wide ? 'wmain' : 'main'}-dryrun.txt", text, {
      'kind' => 'derived compiler-driver dry run; no compilation or linking executed',
      'issuer' => 'installed GCC', 'revision' => 'GCC 16.2.0; exact package build commit unknown',
      'input_path' => gcc, 'input_sha256' => Digest::SHA256.file(gcc).hexdigest,
      'input_bytes' => File.size(gcc), 'command_argv' => argv,
      'observation_stream' => 'combined stdout/stderr', 'normalization' => 'None',
      'interpretation' => '-### only prints driver actions. -save-temps=obj stabilizes printed temporary names; it does not execute those actions. Empty input is not an ordinary application acceptance test.'
    })
  end
end
{
  'crt2.obj' => '/Users/int/.cache/zig/o/152791cf652f60c4402bea4673565078/crt2.obj',
  'libmingw32.lib' => '/Users/int/.cache/zig/o/afae1d826d2eb237b5dc8152fbe13fae/libmingw32.lib'
}.each do |name, input|
  argv = ["#{LLVM}/llvm-nm", '-u', input]
  text, status = Open3.capture2(*argv)
  raise "cached ARM64 observation failed: #{input}" unless status.success?
  generated("producer/zig-arm64-#{name}.txt", text, {
    'kind' => 'derived cached object/archive undefined-symbol observation',
    'issuer' => 'local Zig cache; producer invocation and source revision unknown',
    'revision' => 'unknown', 'input_path' => input,
    'input_sha256' => Digest::SHA256.file(input).hexdigest, 'input_bytes' => File.size(input),
    'command_argv' => argv, 'normalization' => 'None; complete llvm-nm stdout',
    'interpretation' => 'Observed bytes are identified by hash only. Do not equate cache producers with a retained source revision or infer final PE imports from archive undefined symbols.'
  })
end

fixture_root = File.expand_path('../../../../tests/fixtures/user/windows/crt_stdio', ROOT)
%w[x86 x64 arm64].each do |arch|
  %w[main wmain].each do |kind|
    input = File.join(fixture_root, "bin/#{arch}/ordinary/#{kind}.exe")
    bytes = File.binread(input)
    argv = ["#{LLVM}/llvm-readobj", '--coff-imports', '-']
    text, status = Open3.capture2(*argv, stdin_data: bytes)
    raise "ordinary PE import observation failed: #{input}" unless status.success?
    generated("producer/ordinary-#{arch}-#{kind}-imports.txt", text, {
      'kind' => 'derived final compiler-produced ordinary PE import observation',
      'issuer' => 'repository fixture producer; genuine linked IAT observation, not native execution oracle',
      'revision' => 'fixture bytes identified by input hash; final producer recipe and source provenance belong to fixture manifest',
      'input_path' => input, 'input_sha256' => Digest::SHA256.hexdigest(bytes),
      'input_bytes' => bytes.bytesize, 'command_argv' => argv,
      'stdin_source' => 'input_path', 'normalization' => 'None; complete llvm-readobj stdout',
      'fixture_manifest' => '../../../../tests/fixtures/user/windows/crt_stdio/manifest.toml',
      'interpretation' => 'An actual linked import graph is not evidence all its leaves are implemented or ordinary startup accepted. No binary fixture is copied by this archive.'
    })
  end
end

tools = (%w[llvm-nm llvm-ar llvm-readobj llvm-objdump].map { |name| "#{LLVM}/#{name}" } + gcc_paths).map do |path|
  version, status = Open3.capture2(path, '--version')
  raise "tool version failed: #{path}" unless status.success?
  { 'path' => path, 'version' => version.strip, 'sha256' => Digest::SHA256.file(path).hexdigest }
end
manifest = {
  'schema' => 1, 'retrieved' => DATE, 'baseline_head' => BASELINE,
  'baseline_receipt' => 'Root verified tracked tree/index clean and reserved this new archive; archive agent performed no Git operations',
  'purpose' => 'Genuine CRT mode and standard-stream/byte-I/O public contracts and compiler compatibility evidence; native private FILE internals unknown',
  'reuse_policy' => 'Prior inputs are verified by hash/size and not rewritten; their original producer/extraction/license metadata is retained',
  'acquisition_script_sha256' => Digest::SHA256.file(__FILE__).hexdigest,
  'tools' => tools, 'sources' => ENTRIES
}
File.binwrite(File.join(ROOT, 'sources.json'), JSON.pretty_generate(manifest) + "\n")
puts "verified #{ENTRIES.length} inputs; #{ENTRIES.sum { |entry| entry.fetch('bytes') }} referenced bytes"
