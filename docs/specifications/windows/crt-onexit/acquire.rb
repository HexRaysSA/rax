#!/usr/bin/env ruby
# Byte-preserving evidence acquisition; no implementation or guest fixture build.
require 'digest'
require 'fileutils'
require 'json'

ROOT = File.expand_path(__dir__)
DATE = '2026-09-27'
BASELINE = '3efe07a63ab935815d84ea4a48958282672a9059'
CPP = 'f2355df9f7136d8a2097193fc507882a7caeb5f5'
MINGW = '9b3dd0125792fe94d16cacdc596dbd42fca1b369'
ENTRIES = []

def reuse(archive, paths)
  manifest = File.join(ROOT, "../#{archive}/sources.json")
  prior = JSON.parse(File.binread(manifest))
  paths.each do |path|
    old = prior.fetch('sources').find { |entry| entry.fetch('path') == path }
    raise "missing retained source #{archive}/#{path}" unless old
    relative = "../#{archive}/#{path}"
    absolute = File.join(ROOT, relative)
    raise "retained source changed #{relative}" unless
      Digest::SHA256.file(absolute).hexdigest == old.fetch('sha256') &&
      File.size(absolute) == old.fetch('bytes')
    ENTRIES << old.merge('path' => relative, 'reuse_manifest' => "../#{archive}/sources.json")
  end
end

def download(path, url, metadata)
  absolute = File.join(ROOT, path)
  FileUtils.mkdir_p(File.dirname(absolute))
  raise "download failed: #{url}" unless system('curl', '--fail', '--silent', '--show-error', url, '-o', absolute)
  bytes = File.binread(absolute)
  if path.end_with?('.md')
    metadata = metadata.merge('title' => bytes[/^title:\s*"?([^"\r\n]+)"?$/, 1],
                              'document_date' => bytes[/^ms\.date:\s*"?([^"\r\n]+)"?$/, 1])
  end
  ENTRIES << metadata.merge('path' => path, 'source_url' => url, 'retrieved' => DATE,
                           'normalization' => 'None', 'bytes' => bytes.bytesize,
                           'sha256' => Digest::SHA256.hexdigest(bytes))
end

reuse('crt-initializers', %w[
  microsoft/execute-onexit-table-initialize-onexit-table-register-onexit-function.md
  microsoft/atexit.md microsoft/onexit-onexit-m.md microsoft/exit-exit-exit.md
  microsoft/cexit-c-exit.md microsoft/quick-exit1.md microsoft/LICENSE microsoft/LICENSE-CODE
  mingw14/onexit_table.c mingw14/corecrt-startup-excerpt.h mingw14/crtexe.c
  mingw14/crtdll.c mingw14/msvcrt.def.in mingw14/func.def.in mingw14/COPYING
  mingw14/DISCLAIMER.PD zig/corecrt-startup-excerpt.h zig/api-ms-win-crt-runtime.def.in
  zig/COPYING symbols/msvcrt-os-x86.txt symbols/msvcrt-os-x64.txt
  symbols/ucrtbase-x86.txt symbols/ucrtbase-x64.txt
])
reuse('crt-startup', %w[zig/ucrtbase-common.def.in])

download('microsoft/dllonexit.md',
         "https://raw.githubusercontent.com/MicrosoftDocs/cpp-docs/#{CPP}/docs/c-runtime-library/dllonexit.md", {
  'kind' => 'publisher documentation', 'issuer' => 'Microsoft', 'revision' => CPP,
  'canonical_url' => 'https://learn.microsoft.com/en-us/cpp/c-runtime-library/dllonexit?view=msvc-170',
  'license' => 'CC-BY-4.0 prose; MIT code samples; owning retained MicrosoftDocs licenses'
})
download('mingw14/onexit.c',
         "https://raw.githubusercontent.com/mingw-w64/mingw-w64/#{MINGW}/mingw-w64-crt/misc/_onexit.c", {
  'kind' => 'upstream compatibility implementation; not a native Microsoft CRT oracle',
  'issuer' => 'MinGW-w64', 'revision' => MINGW, 'release' => 'v14.0.0',
  'license' => 'Public Domain input notice; owning retained MinGW COPYING and DISCLAIMER.PD'
})

manifest = {
  'schema' => 1, 'retrieved' => DATE, 'baseline_head' => BASELINE,
  'purpose' => 'Explicit UCRT onexit table contract and bounded legacy/global termination audit; native Windows private behavior unknown',
  'reuse_policy' => 'Frozen prior entries retain original producer, extraction, license and symbol-observation metadata; no prior bytes changed',
  'sources' => ENTRIES
}
File.write(File.join(ROOT, 'sources.json'), JSON.pretty_generate(manifest) + "\n")
puts "verified #{ENTRIES.length} inputs; #{ENTRIES.sum { |entry| entry.fetch('bytes') }} referenced bytes"
