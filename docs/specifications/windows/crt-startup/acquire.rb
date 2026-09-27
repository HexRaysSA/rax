#!/usr/bin/env ruby
# Byte-preserving evidence acquisition; no guest, implementation, or fixture build.
require 'digest'
require 'fileutils'
require 'json'
require 'open3'

ROOT = File.expand_path(__dir__)
DATE = '2026-09-27'
BASELINE = '0753ca1c0b769da93d24390d1f24c4aad070b9d2'
CPP = 'f2355df9f7136d8a2097193fc507882a7caeb5f5'
SDK = 'a4fd3f7efe2e3378a96c6fe5a6a9455eba9fa021'
MINGW = '9b3dd0125792fe94d16cacdc596dbd42fca1b369'
DOTNET = '33baf8ee337b20dd0f184b69a6f09be92850bf9e'
PKG = '/opt/homebrew/Cellar/mingw-w64/14.0.0_3'
ZIG = '/opt/homebrew/Cellar/zig/0.16.0_1/lib/zig/libc'
NM = '/Users/int/local/bin/llvm-nm'
ENTRIES = []

def record(path, metadata)
  absolute = File.join(ROOT, path)
  bytes = File.binread(absolute)
  if path.end_with?('.md')
    metadata = metadata.merge('title' => bytes[/^title:\s*"?([^"\r\n]+)"?\r?$/, 1],
                              'document_date' => bytes[/^(?:ms\.date|ms_date):\s*"?([^"\r\n]+)"?\r?$/, 1])
  end
  ENTRIES << metadata.merge('path' => path, 'retrieved' => DATE,
                           'sha256' => Digest::SHA256.hexdigest(bytes), 'bytes' => bytes.bytesize)
end

def download(path, url, metadata)
  absolute = File.join(ROOT, path)
  FileUtils.mkdir_p(File.dirname(absolute))
  raise "download failed: #{url}" unless system('curl', '--fail', '--silent', '--show-error', url, '-o', absolute)
  record(path, metadata.merge('source_url' => url, 'normalization' => 'None'))
end

def installed(path, input, metadata, range = nil)
  absolute = File.join(ROOT, path)
  FileUtils.mkdir_p(File.dirname(absolute))
  bytes = File.binread(input)
  result = range ? bytes.lines.values_at(*range).join : bytes
  File.binwrite(absolute, result)
  recipe = range ? "sed -n '#{range.map { |n| "#{n + 1}p" }.join(';')}' #{input}" : "complete byte copy of #{input}"
  record(path, metadata.merge('input_path' => input, 'input_sha256' => Digest::SHA256.hexdigest(bytes),
                             'extraction_command' => recipe, 'normalization' => 'None; complete input or exact line subsequence'))
end

# Reuse frozen evidence instead of assigning a new producer revision or normalizing it.
prior = JSON.parse(File.binread(File.join(ROOT, '../crt-initializers/sources.json')))
%w[microsoft/getmainargs-wgetmainargs.md microsoft/environ-wenviron.md
   microsoft/internal-crt-globals-and-functions.md microsoft/parsing-c-command-line-arguments.md
   microsoft/LICENSE microsoft/LICENSE-CODE mingw14/msvcrt.def.in mingw14/func.def.in
   mingw14/COPYING mingw14/DISCLAIMER.PD zig/ucrt__getmainargs.c zig/ucrt__wgetmainargs.c
   zig/crtexe.c zig/COPYING].each do |path|
  old = prior.fetch('sources').find { |entry| entry.fetch('path') == path }
  raise "missing retained source #{path}" unless old
  relative = "../crt-initializers/#{path}"
  raise "retained source changed #{path}" unless Digest::SHA256.file(File.join(ROOT, relative)).hexdigest == old.fetch('sha256')
  ENTRIES << old.merge('path' => relative, 'reuse_manifest' => '../crt-initializers/sources.json')
end

cpp_root = "https://raw.githubusercontent.com/MicrosoftDocs/cpp-docs/#{CPP}/docs"
{
  'argc-argv-wargv' => 'c-runtime-library', 'acmdln-tcmdln-wcmdln' => 'c-runtime-library',
  'pgmptr-wpgmptr' => 'c-runtime-library', 'global-state' => 'c-runtime-library',
  'get-pgmptr' => 'c-runtime-library/reference', 'get-wpgmptr' => 'c-runtime-library/reference',
  'set-new-mode' => 'c-runtime-library/reference', 'query-new-mode' => 'c-runtime-library/reference',
  'set-new-handler' => 'c-runtime-library/reference', 'query-new-handler' => 'c-runtime-library/reference',
  'expanding-wildcard-arguments' => 'c-language'
}.each do |page, parent|
  download("microsoft/#{page}.md", "#{cpp_root}/#{parent}/#{page}.md", {
    'kind' => 'publisher documentation', 'issuer' => 'Microsoft', 'revision' => CPP,
    'canonical_url' => "https://learn.microsoft.com/en-us/cpp/#{parent}/#{page}?view=msvc-170",
    'license' => 'CC-BY-4.0 prose; MIT code samples; retained ../crt-initializers/microsoft licenses'
  })
end

sdk_root = "https://raw.githubusercontent.com/MicrosoftDocs/sdk-api/#{SDK}"
{
  'widechartomultibyte' => 'stringapiset', 'multibytetowidechar' => 'stringapiset',
  'getacp' => 'winnls', 'getcpinfo' => 'winnls',
  'getcommandlinea' => 'processenv', 'getcommandlinew' => 'processenv'
}.each do |page, header|
  download("sdk-api/#{page}.md", "#{sdk_root}/sdk-api-src/content/#{header}/nf-#{header}-#{page}.md", {
    'kind' => 'publisher documentation', 'issuer' => 'Microsoft', 'revision' => SDK,
    'canonical_url' => "https://learn.microsoft.com/en-us/windows/win32/api/#{header}/nf-#{header}-#{page}",
    'license' => 'CC-BY-4.0 prose; MIT code samples; sdk-api licenses retained'
  })
end
%w[LICENSE LICENSE-CODE].each do |name|
  download("sdk-api/#{name}", "#{sdk_root}/#{name}", { 'kind' => 'license', 'issuer' => 'MicrosoftDocs', 'revision' => SDK })
end

{
  'CP1252.TXT' => 'WINDOWS/CP1252.TXT',
  'bestfit1252.txt' => 'WindowsBestFit/bestfit1252.txt',
  'windows-bestfit-readme.txt' => 'WindowsBestFit/readme.txt'
}.each do |local, remote|
  url = "https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/#{remote}"
  download("unicode/#{local}", url, {
    'kind' => 'Microsoft mapping data distributed by Unicode; not native DLL observation',
    'issuer' => 'Microsoft / Unicode', 'revision' => local == 'CP1252.TXT' ? 'Table 2.01, Unicode 2.0, 1998-04-15' : 'Producer revision/date unknown; mutable URL pinned by retained hash',
    'canonical_url' => url, 'license' => 'Unicode data-files permission notice retained as unicode/LICENSE; no additional file-local notice'
  })
end
download('unicode/LICENSE', 'https://www.unicode.org/license.txt', {
  'kind' => 'license', 'issuer' => 'Unicode', 'revision' => 'Unicode License V3, copyright 1991-2026; mutable URL pinned by hash'
})
dotnet_root = "https://raw.githubusercontent.com/dotnet/runtime/#{DOTNET}"
download('dotnet/FileSystemName.cs', "#{dotnet_root}/src/libraries/System.Private.CoreLib/src/System/IO/Enumeration/FileSystemName.cs", {
  'kind' => 'publisher implementation source; not native Windows CRT oracle', 'issuer' => '.NET Foundation / Microsoft',
  'revision' => DOTNET, 'license' => 'MIT; dotnet/LICENSE.TXT retained',
  'canonical_url' => "https://github.com/dotnet/runtime/blob/#{DOTNET}/src/libraries/System.Private.CoreLib/src/System/IO/Enumeration/FileSystemName.cs"
})
download('dotnet/LICENSE.TXT', "#{dotnet_root}/LICENSE.TXT", { 'kind' => 'license', 'issuer' => '.NET Foundation / Microsoft', 'revision' => DOTNET })

mingw_root = "https://raw.githubusercontent.com/mingw-w64/mingw-w64/#{MINGW}/mingw-w64-crt"
%w[msvcrt__getmainargs.c msvcrt__wgetmainargs.c _get_pgmptr.c _get_wpgmptr.c].each do |name|
  download("mingw14/#{name}", "#{mingw_root}/misc/#{name}", {
    'kind' => 'upstream compatibility implementation; not native Microsoft CRT oracle', 'issuer' => 'MinGW-w64',
    'revision' => MINGW, 'release' => 'v14.0.0',
    'license' => 'Public Domain input notice; owning ../crt-initializers/mingw14/COPYING and DISCLAIMER.PD retained'
  })
end
header_meta = { 'kind' => 'installed public header', 'issuer' => 'MinGW-w64',
                'revision' => 'Homebrew MinGW-w64 14.0.0_3; exact build commit unknown',
                'license' => 'Public Domain input notice; owning ../crt-initializers/mingw14/COPYING and DISCLAIMER.PD retained' }
%w[corecrt_startup.h new.h].each do |name|
  installed("mingw14/#{name}", "#{PKG}/toolchain-x86_64/x86_64-w64-mingw32/include/#{name}", header_meta)
end
installed('mingw14/stdlib-startup-excerpt.h', "#{PKG}/toolchain-x86_64/x86_64-w64-mingw32/include/stdlib.h",
          header_meta.merge('kind' => 'installed public header excerpt'), (0...5).to_a + (159...230).to_a)
# Exact line subsequences, not standalone compilable or native SDK headers.
# winnt.h lacks the Public Domain notice; its owning COPYING uses ZPL 2.1.
context_ranges = (0...5).to_a + (1503...1508).to_a + [1597] + (1804...1925).to_a +
                 [1943] + (2225...2343).to_a + [2528] + (2624...2691).to_a + (3056...3092).to_a
license_input = "#{PKG}/COPYING"
license_hash = Digest::SHA256.file(license_input).hexdigest
raise 'installed MinGW COPYING differs from retained license' unless
  license_hash == Digest::SHA256.file(File.join(ROOT, '../crt-initializers/mingw14/COPYING')).hexdigest
installed('mingw14/winnt-exception-context-excerpt.h',
          "#{PKG}/toolchain-x86_64/x86_64-w64-mingw32/include/winnt.h",
          header_meta.merge('kind' => 'installed public exception/context header excerpt; not native SDK/private-layout oracle',
                            'license' => 'ZPL 2.1; file notice and owning ../crt-initializers/mingw14/COPYING retained',
                            'license_input_path' => license_input, 'license_input_sha256' => license_hash,
                            'selected_layout' => 'x86/x64/ARM64 public CONTEXT; EXCEPTION_RECORD/EXCEPTION_POINTERS'),
          context_ranges)
zig_meta = { 'issuer' => 'MinGW-w64 bundled with Zig',
             'revision' => 'Zig 0.16.0 Homebrew 0.16.0_1; bundled upstream commit unknown',
             'license' => 'Input notice plus owning ../crt-initializers/zig/COPYING' }
installed('zig/internal-startup-excerpt.h', "#{ZIG}/mingw/include/internal.h",
          zig_meta.merge('kind' => 'installed internal header excerpt; not native private layout oracle'), (0...5).to_a + (95...127).to_a)
zig_license_input = "#{ZIG}/mingw/COPYING"
zig_license_hash = Digest::SHA256.file(zig_license_input).hexdigest
raise 'installed Zig COPYING differs from retained license' unless
  zig_license_hash == Digest::SHA256.file(File.join(ROOT, '../crt-initializers/zig/COPYING')).hexdigest
installed('zig/winnt-exception-context-excerpt.h', "#{ZIG}/include/any-windows-any/winnt.h",
          zig_meta.merge('kind' => 'installed public exception/context header excerpt; not native SDK/private-layout oracle',
                         'license' => 'ZPL 2.1; file notice and owning ../crt-initializers/zig/COPYING retained',
                         'license_input_path' => zig_license_input, 'license_input_sha256' => zig_license_hash,
                         'selected_layout' => 'x86/x64/ARM64 public CONTEXT; EXCEPTION_RECORD/EXCEPTION_POINTERS'),
          context_ranges.map { |line| line < 5 ? line : line - 8 })
%w[ucrtbase-common.def.in api-ms-win-crt-runtime-l1-1-0.def.in api-ms-win-crt-environment-l1-1-0.def
   api-ms-win-crt-heap-l1-1-0.def].each do |name|
  installed("zig/#{name}", "#{ZIG}/mingw/lib-common/#{name}", zig_meta.merge('kind' => 'installed import definition; not measured native export table'))
end
installed('zig/wildcard.c', "#{ZIG}/mingw/crt/wildcard.c", zig_meta.merge('kind' => 'installed compatibility implementation; not native CRT oracle'))
%w[crtexewin.c ucrtexewin.c].each do |name|
  installed("zig/#{name}", "#{ZIG}/mingw/crt/#{name}", zig_meta.merge('kind' => 'installed WinMain compatibility glue; not native CRT oracle'))
end

names = %w[__argc __argv __wargv __initenv __winitenv __p___initenv __p___winitenv __getmainargs __wgetmainargs __msvcrt_getmainargs __msvcrt_wgetmainargs
           __p___argc __p___argv __p___wargv __p__acmdln __p__wcmdln __p__environ __p__wenviron __p__pgmptr __p__wpgmptr
           _acmdln _wcmdln _environ _wenviron _pgmptr _wpgmptr _get_environ _get_wenviron _get_pgmptr _get_wpgmptr
           _configure_narrow_argv _configure_wide_argv _initialize_narrow_environment _initialize_wide_environment
           _get_initial_narrow_environment _get_initial_wide_environment _get_narrow_winmain_command_line
           _get_wide_winmain_command_line _set_app_type __set_app_type _query_app_type _set_new_mode _query_new_mode
           _set_new_handler _query_new_handler]
%w[x86 x64].each do |arch|
  tuple = arch == 'x86' ? %w[i686 i686-w64-mingw32] : %w[x86_64 x86_64-w64-mingw32]
  prefix = arch == 'x86' ? '_' : ''
  pattern = "( I __imp_| T | D __imp_)(#{prefix}(#{names.join('|')})|\\?_(set|query)_new_(mode|handler)@@[^ ]+)$"
  %w[msvcrt-os ucrtbase].each do |runtime|
    input = "#{PKG}/toolchain-#{tuple[0]}/#{tuple[1]}/lib/lib#{runtime}.a"
    output, status = Open3.capture2(NM, '-A', '-g', input)
    raise "nm failed #{input}" unless status.success?
    selected = output.lines.select { |line| line.match?(Regexp.new(pattern)) }.join
    raise "empty observations #{input}" if selected.empty?
    path = "symbols/#{runtime}-#{arch}.txt"
    FileUtils.mkdir_p(File.join(ROOT, 'symbols'))
    File.binwrite(File.join(ROOT, path), selected)
    record(path, { 'kind' => 'derived import/archive symbol observation; not native DLL export inventory',
                   'issuer' => 'MinGW-w64', 'revision' => 'Homebrew MinGW-w64 14.0.0_3',
                   'input_path' => input, 'input_sha256' => Digest::SHA256.file(input).hexdigest,
                   'command' => "#{NM} -A -g #{input} | rg '#{pattern}'",
                   'interpretation' => 'I __imp_ denotes an import; T+D __imp_ in compatibility members denotes a shim. DEF aliases establish actual imported names.' })
  end
end
version, status = Open3.capture2(NM, '--version')
raise 'nm version failed' unless status.success?
manifest = { 'schema' => 1, 'retrieved' => DATE, 'baseline_head' => BASELINE,
             'purpose' => 'Primary CRT argv/environment/startup binding and encoding evidence; no native Windows oracle',
             'tool' => { 'path' => NM, 'version' => version.strip, 'sha256' => Digest::SHA256.file(NM).hexdigest },
             'sources' => ENTRIES }
File.write(File.join(ROOT, 'sources.json'), JSON.pretty_generate(manifest) + "\n")
local = ENTRIES.reject { |entry| entry['reuse_manifest'] }
puts "#{ENTRIES.size} verified inputs: #{local.size} local, #{ENTRIES.size - local.size} reused; #{local.sum { |entry| entry['bytes'] }} local bytes"
