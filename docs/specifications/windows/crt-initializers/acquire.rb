#!/usr/bin/env ruby
# Mechanical byte-preserving reference acquisition, never implementation/PE generation.
require 'digest'
require 'fileutils'
require 'json'
require 'open3'

ROOT = File.expand_path(__dir__)
DATE = '2026-09-27'
CPP = 'f2355df9f7136d8a2097193fc507882a7caeb5f5'
MINGW = '9b3dd0125792fe94d16cacdc596dbd42fca1b369'
ZIG = '/opt/homebrew/Cellar/zig/0.16.0_1/lib/zig/libc'
PKG = '/opt/homebrew/Cellar/mingw-w64/14.0.0_3'
NM = '/Users/int/local/bin/llvm-nm'
ENTRIES = []

def record(path, metadata)
  absolute = File.join(ROOT, path)
  if path.end_with?('.md')
    bytes = File.binread(absolute)
    metadata = metadata.merge(
      'title' => bytes[/^title:\s*"?([^"\r\n]+)"?$/, 1],
      'document_date' => bytes[/^ms\.date:\s*"?([^"\r\n]+)"?$/, 1]
    )
  end
  ENTRIES << metadata.merge(
    'path' => path, 'retrieved' => DATE,
    'sha256' => Digest::SHA256.file(absolute).hexdigest,
    'bytes' => File.size(absolute)
  )
end

def download(path, url, metadata)
  absolute = File.join(ROOT, path)
  FileUtils.mkdir_p(File.dirname(absolute))
  raise "download failed: #{url}" unless system(
    'curl', '--fail', '--silent', '--show-error', url, '-o', absolute
  )
  record(path, metadata.merge('source_url' => url, 'normalization' => 'None'))
end

def installed(path, input, recipe, metadata)
  absolute = File.join(ROOT, path)
  FileUtils.mkdir_p(File.dirname(absolute))
  bytes = File.binread(input)
  result = yield(bytes)
  File.binwrite(absolute, result)
  record(path, metadata.merge(
    'input_path' => input, 'input_sha256' => Digest::SHA256.hexdigest(bytes),
    'extraction_command' => recipe,
    'normalization' => 'None; complete input or exact line subsequence'
  ))
end

cpp_root = "https://raw.githubusercontent.com/MicrosoftDocs/cpp-docs/#{CPP}"
references = %w[initterm-initterm-e exit-exit-exit atexit cexit-c-exit quick-exit1 onexit-onexit-m]
references.each do |page|
  download("microsoft/#{page}.md", "#{cpp_root}/docs/c-runtime-library/reference/#{page}.md", {
    'kind' => 'publisher documentation', 'issuer' => 'Microsoft', 'revision' => CPP,
    'canonical_url' => "https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/#{page}?view=msvc-170",
    'license' => 'CC-BY-4.0 prose; MIT code samples'
  })
end
%w[crt-initialization execute-onexit-table-initialize-onexit-table-register-onexit-function getmainargs-wgetmainargs environ-wenviron internal-crt-globals-and-functions].each do |page|
  download("microsoft/#{page}.md", "#{cpp_root}/docs/c-runtime-library/#{page}.md", {
    'kind' => 'publisher documentation', 'issuer' => 'Microsoft', 'revision' => CPP,
    'canonical_url' => "https://learn.microsoft.com/en-us/cpp/c-runtime-library/#{page}?view=msvc-170",
    'license' => 'CC-BY-4.0 prose; MIT code samples'
  })
end
download('microsoft/parsing-c-command-line-arguments.md', "#{cpp_root}/docs/c-language/parsing-c-command-line-arguments.md", {
  'kind' => 'publisher documentation', 'issuer' => 'Microsoft', 'revision' => CPP,
  'canonical_url' => 'https://learn.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments?view=msvc-170',
  'license' => 'CC-BY-4.0 prose; MIT code samples'
})
%w[LICENSE LICENSE-CODE].each do |name|
  download("microsoft/#{name}", "#{cpp_root}/#{name}", {
    'kind' => 'license', 'issuer' => 'MicrosoftDocs', 'revision' => CPP
  })
end

mingw_root = "https://raw.githubusercontent.com/mingw-w64/mingw-w64/#{MINGW}"
{
  'initterm_e.c' => 'misc/_initterm_e.c',
  'crtexe.c' => 'crt/crtexe.c',
  'crtdll.c' => 'crt/crtdll.c',
  'cinitexe.c' => 'crt/cinitexe.c',
  'onexit_table.c' => 'misc/onexit_table.c'
}.each do |local, upstream|
  download("mingw14/#{local}", "#{mingw_root}/mingw-w64-crt/#{upstream}", {
    'kind' => 'upstream implementation source; not native Microsoft CRT oracle',
    'issuer' => 'MinGW-w64', 'revision' => MINGW, 'release' => 'v14.0.0',
    'license' => local == 'cinitexe.c' ? 'ZPL-2.1 under owning COPYING; input has no Public Domain override' : 'Public Domain notice in input; owning COPYING and DISCLAIMER.PD retained'
  })
end
%w[COPYING DISCLAIMER.PD].each do |name|
  download("mingw14/#{name}", "#{mingw_root}/#{name}", {
    'kind' => 'license', 'issuer' => 'MinGW-w64', 'revision' => MINGW
  })
end
{ 'msvcrt.def.in' => 'lib-common/msvcrt.def.in',
  'func.def.in' => 'def-include/func.def.in' }.each do |name, upstream|
  download("mingw14/#{name}", "#{mingw_root}/mingw-w64-crt/#{upstream}", {
    'kind' => 'upstream import definition; not a measured native DLL export table',
    'issuer' => 'MinGW-w64', 'revision' => MINGW, 'release' => 'v14.0.0',
    'license' => 'MinGW-w64 COPYING and input notices'
  })
end

zig_metadata = {
  'kind' => 'installed implementation source; not native Microsoft CRT oracle',
  'issuer' => 'MinGW-w64 bundled with Zig',
  'revision' => 'Zig 0.16.0 Homebrew 0.16.0_1; bundled MinGW exact upstream commit unknown',
  'license' => 'Input notice plus owning zig/COPYING'
}
%w[crtexe.c crtdll.c cinitexe.c].each do |name|
  input = "#{ZIG}/mingw/crt/#{name}"
  installed("zig/#{name}", input, "complete byte copy of #{input}", zig_metadata) { |bytes| bytes }
end
%w[ucrt__getmainargs.c ucrt__wgetmainargs.c].each do |name|
  input = "#{ZIG}/mingw/misc/#{name}"
  installed("zig/#{name}", input, "complete byte copy of #{input}", zig_metadata) { |bytes| bytes }
end
input = "#{ZIG}/mingw/COPYING"
installed('zig/COPYING', input, "complete byte copy of #{input}", zig_metadata.merge('kind' => 'license')) { |bytes| bytes }
input = "#{ZIG}/mingw/lib-common/api-ms-win-crt-runtime-l1-1-0.def.in"
installed('zig/api-ms-win-crt-runtime.def.in', input, "complete byte copy of #{input}", zig_metadata.merge('kind' => 'installed import definition')) { |bytes| bytes }
input = "#{ZIG}/mingw/lib-common/ucrtbase-common.def.in"
lines = [1, 2, 3, 4, 5, 63, 268, 273, 303, 304, 343, 348, 488, 490, 491, 1913, 1914, 2331, 2521]
installed('zig/ucrtbase-startup-def-excerpt.def.in', input,
          "sed -n '#{lines.map { |line| "#{line}p" }.join(';')}' #{input}",
          zig_metadata.merge('kind' => 'installed import definition excerpt')) do |bytes|
  rows = bytes.lines
  lines.map { |line| rows.fetch(line - 1) }.join
end
{
  'mingw14/corecrt-startup-excerpt.h' => "#{PKG}/toolchain-x86_64/x86_64-w64-mingw32/include/corecrt_startup.h",
  'zig/corecrt-startup-excerpt.h' => "#{ZIG}/include/any-windows-any/corecrt_startup.h"
}.each do |path, input|
  installed(path, input, "sed -n '1,5p;49,68p' #{input}", {
    'kind' => 'installed public header excerpt', 'issuer' => 'MinGW-w64',
    'revision' => path.start_with?('mingw14/') ? 'Homebrew MinGW-w64 14.0.0_3; exact upstream build commit unknown' : zig_metadata['revision'],
    'license' => 'Public Domain header notice; COPYING and DISCLAIMER.PD retained'
  }) do |bytes|
    rows = bytes.lines
    (rows[0, 5] + rows[48, 20]).join
  end
end
input = "#{PKG}/toolchain-x86_64/x86_64-w64-mingw32/include/stdlib.h"
installed('mingw14/stdlib-startup-excerpt.h', input, "sed -n '1,5p;160,236p' #{input}", {
  'kind' => 'installed public header excerpt', 'issuer' => 'MinGW-w64',
  'revision' => 'Homebrew MinGW-w64 14.0.0_3; exact upstream build commit unknown',
  'license' => 'Public Domain header notice; COPYING and DISCLAIMER.PD retained'
}) do |bytes|
  rows = bytes.lines
  (rows[0, 5] + rows[159, 77]).join
end

names = '_initterm|_initterm_e|atexit|_crt_atexit|_onexit|onexit|__dllonexit|_execute_onexit_table|_initialize_onexit_table|_register_onexit_function|exit|_exit|_Exit|_cexit|_c_exit|quick_exit|at_quick_exit|_crt_at_quick_exit'
%w[x86 x64].each do |arch|
  tuple = arch == 'x86' ? ['i686', 'i686-w64-mingw32'] : ['x86_64', 'x86_64-w64-mingw32']
  %w[msvcrt-os ucrtbase].each do |runtime|
    input = "#{PKG}/toolchain-#{tuple[0]}/#{tuple[1]}/lib/lib#{runtime}.a"
    prefix = arch == 'x86' ? '_' : ''
    pattern = "( I __imp_| T | D __imp_)(#{prefix}(#{names}))$"
    observation, status = Open3.capture2(NM, '-A', '-g', input)
    raise "llvm-nm failed: #{input}" unless status.success?
    filtered = observation.lines.select { |line| line.match?(Regexp.new(pattern)) }.join
    raise "empty observation: #{input}" if filtered.empty?
    path = "symbols/#{runtime}-#{arch}.txt"
    FileUtils.mkdir_p(File.join(ROOT, 'symbols'))
    File.binwrite(File.join(ROOT, path), filtered)
    record(path, {
      'kind' => 'derived import/archive symbol observation; not native DLL export oracle',
      'issuer' => 'MinGW-w64', 'revision' => 'Homebrew MinGW-w64 14.0.0_3',
      'input_path' => input, 'input_sha256' => Digest::SHA256.file(input).hexdigest,
      'command' => "#{NM} -A -g #{input} | rg '#{pattern}'",
      'interpretation' => 'I __imp_ is an import member; T implementation plus D __imp_ is a local shim, not evidence of native named IAT availability'
    })
  end
end

tools, status = Open3.capture2(NM, '--version')
raise 'llvm-nm version failed' unless status.success?
manifest = {
  'schema' => 1, 'retrieved' => DATE,
  'purpose' => 'Constructor traversal contract and bounded future startup/termination dependency audit; no native Windows oracle',
  'baseline_head' => 'b7498e58030bc0317cfa96845b509c9335c8fb30',
  'tool' => { 'path' => NM, 'version' => tools.strip, 'sha256' => Digest::SHA256.file(NM).hexdigest },
  'mingw_tag' => { 'name' => 'v14.0.0', 'tag_object' => 'e25dbe3428ce40d7321606a5642623a5a6e3da73', 'commit' => MINGW,
                   'resolution_url' => 'https://api.github.com/repos/mingw-w64/mingw-w64/git/tags/e25dbe3428ce40d7321606a5642623a5a6e3da73' },
  'sources' => ENTRIES
}
File.write(File.join(ROOT, 'sources.json'), JSON.pretty_generate(manifest) + "\n")
puts "retained #{ENTRIES.length} sources, #{ENTRIES.sum { |entry| entry['bytes'] }} bytes"
