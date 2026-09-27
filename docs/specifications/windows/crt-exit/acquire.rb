#!/usr/bin/env ruby
# Retain public prose and metadata only; proprietary SDK bytes stay temporary.
require 'json'
require 'digest'
require 'fileutils'

ARCHIVE = File.expand_path(__dir__)
PARENT = File.expand_path('../crt-termination', ARCHIVE)
CPP_REV = 'f2355df9f7136d8a2097193fc507882a7caeb5f5'
EXIT_DATE = '2026-09-27'
EXIT_BASELINE = '02f28dbb4b6cc51e394987b7784ca34de965e2f5'
HELPER_SHA = '09300dada01d906063cd04372c85d1249464283189039f23d342a066ee672a6d'
PARENT_SHA = '8eb3cf9b4cc47d6ab65a6f3f436ea9558ff556e01a6a2850ba7592b32c82af8c'
helper_path = File.join(PARENT, 'acquire.rb')
raise 'changed SDK helper' unless Digest::SHA256.file(helper_path).hexdigest == HELPER_SHA
# Only the byte-range/ZIP functions are loaded; the parent's acquisition driver
# and repository writes are never evaluated.
eval(File.read(helper_path).split("\nif ARGV == ").first, TOPLEVEL_BINDING, helper_path)
parent_path = File.join(PARENT, 'sources.json')
raise 'changed parent receipt' unless Digest::SHA256.file(parent_path).hexdigest == PARENT_SHA
parent = JSON.parse(File.binread(parent_path))
EXPORT_NAMES = %w[_Exit _c_exit _cexit _exit _get_terminate _register_thread_local_exe_atexit_callback
                  _set_abort_behavior abort exit quick_exit raise set_terminate signal terminate].freeze
EXPORT_PATTERN = "^  Name: (#{EXPORT_NAMES.join('|')})$"
NEW_MEMBERS = {
  'microsoft-sdk/signal.cpp' => 'c/Source/10.0.26100.0/ucrt/misc/signal.cpp',
  'microsoft-sdk/signal.h' => 'c/Include/10.0.26100.0/ucrt/signal.h',
  'microsoft-sdk/stdlib.h' => 'c/Include/10.0.26100.0/ucrt/stdlib.h',
  'microsoft-sdk/winnt.h' => 'c/Include/10.0.26100.0/um/winnt.h'
}.freeze
PUBLIC = {
  'abort.md' => 'docs/c-runtime-library/reference/abort.md',
  'signal.md' => 'docs/c-runtime-library/reference/signal.md',
  'raise.md' => 'docs/c-runtime-library/reference/raise.md',
  'set-abort-behavior.md' => 'docs/c-runtime-library/reference/set-abort-behavior.md',
  'signal-constants.md' => 'docs/c-runtime-library/signal-constants.md'
}.freeze

def checked_bytes(path, entry)
  bytes = File.binread(path)
  raise "changed #{path}" unless Digest::SHA256.hexdigest(bytes) == entry.fetch('sha256')
  raise "changed size #{path}" if entry['bytes'] && bytes.bytesize != entry['bytes']
  bytes
end

def export_observation(bytes)
  argv = ['/Users/int/local/bin/llvm-readobj', '--coff-exports', '-']
  output, status = Open3.capture2(*argv, stdin_data: bytes)
  raise 'publisher export observer failed' unless status.success?
  selected = output.lines.select { |line| line.match?(Regexp.new(EXPORT_PATTERN)) }.join
  names = selected.lines.map { |line| line.strip.delete_prefix('Name: ') }
  raise 'changed selected publisher names' unless names.sort == EXPORT_NAMES.sort
  [selected, argv]
end

if ARGV == ['--verify'] || ARGV == ['--verify-network']
  manifest = JSON.parse(File.binread(File.join(ARCHIVE, 'sources.json')))
  raise 'changed acquisition script' unless Digest::SHA256.file(__FILE__).hexdigest == manifest.fetch('acquisition_script_sha256')
  manifest.fetch('tools').each do |tool|
    raise "changed tool #{tool.fetch('path')}" unless Digest::SHA256.file(tool.fetch('path')).hexdigest == tool.fetch('sha256')
  end
  entries = nil
  if ARGV == ['--verify-network']
    entries, metadata = sdk_directory
    raise 'changed SDK directory' unless metadata == manifest.fetch('microsoft_sdk_package')
  end
  retained = receipts = remote = commands = 0
  manifest.fetch('sources').each do |entry|
    if entry['path']
      bytes = checked_bytes(File.join(ARCHIVE, entry.fetch('path')), entry)
      retained += 1
      if entry['reuse_manifest']
        previous = JSON.parse(File.binread(File.join(ARCHIVE, entry.fetch('reuse_manifest'))))
        old = previous.fetch('sources').find { |item| item['path'] == entry.fetch('reuse_path') }
        raise 'changed reused metadata' unless old && old.fetch('sha256') == entry.fetch('sha256')
      end
      if entries && entry['command_stdin_sdk_member']
        input = sdk_member(entries.fetch(entry.fetch('command_stdin_sdk_member').fetch('member')))
        raise 'changed publisher DLL' unless Digest::SHA256.hexdigest(input) == entry.fetch('input_sha256')
        actual, = export_observation(input)
        raise 'changed publisher exports' unless actual == bytes
        commands += 1
      elsif entries && !entry['reuse_manifest']
        raise 'changed public document' unless fetch(entry.fetch('source_url')) == bytes
        remote += 1
      end
    else
      receipts += 1
      if entry['reuse_manifest']
        old = parent.fetch('sources').find { |item| item['reference_id'] == entry.fetch('reference_id') }
        raise 'changed reused SDK receipt' unless old && old.fetch('sha256') == entry.fetch('sha256')
      end
      if entries
        bytes = entry['sdk_zip_member'] ? sdk_member(entries.fetch(entry.fetch('sdk_zip_member').fetch('member'))) : fetch(entry.fetch('source_url'))
        raise 'changed SDK source receipt' unless bytes.bytesize == entry.fetch('bytes') && Digest::SHA256.hexdigest(bytes) == entry.fetch('sha256')
        remote += 1
      end
    end
  end
  puts JSON.pretty_generate('retained_hash_size_checks' => retained, 'publisher_source_receipts' => receipts,
                            'network_source_replays' => remote, 'publisher_export_replays' => commands,
                            'tool_hash_checks' => manifest.fetch('tools').size,
                            'raw_sdk_source_committed' => false, 'nuget_signature_verified' => false)
  exit
elsif !ARGV.empty?
  abort 'usage: acquire.rb [--verify|--verify-network]'
end

sources = []
reuse_parent_paths = %w[../crt-initializers/microsoft/LICENSE ../crt-initializers/microsoft/LICENSE-CODE
  ../crt-initializers/microsoft/exit-exit-exit.md ../crt-initializers/microsoft/cexit-c-exit.md
  ../crt-initializers/microsoft/quick-exit1.md ../crt-startup/microsoft/global-state.md]
reuse_parent_paths.each do |path|
  entry = parent.fetch('sources').find { |item| item['path'] == path }
  raise "missing reused input #{path}" unless entry
  bytes = checked_bytes(File.join(PARENT, path), entry)
  sources << entry.merge('path' => path, 'bytes' => bytes.bytesize,
                        'reuse_manifest' => '../crt-termination/sources.json', 'reuse_path' => path)
end
alloc_path = File.expand_path('../crt-foundation/manifest-alloc.json', ARCHIVE)
alloc = JSON.parse(File.binread(alloc_path))
%w[allocation/fastfail.md allocation/parameter-validation.md].each do |path|
  entry = alloc.fetch('sources').find { |item| item['path'] == path }
  raise "missing allocation input #{path}" unless entry
  bytes = checked_bytes(File.expand_path("../crt-foundation/#{path}", ARCHIVE), entry)
  sources << entry.merge('path' => "../crt-foundation/#{path}", 'bytes' => bytes.bytesize,
                        'reuse_manifest' => '../crt-foundation/manifest-alloc.json', 'reuse_path' => path,
                        'license_paths' => entry.fetch('license_paths').map { |license| "../crt-foundation/#{license}" })
end
%w[package.nuspec sdk_license.rtf exit.cpp abort.cpp terminate.cpp initialization.cpp
   corecrt_internal.h per_thread_data.cpp corecrt_startup.h corecrt_terminate.h process.h win_policies.cpp].each do |name|
  id = "microsoft-sdk/#{name}"
  entry = parent.fetch('sources').find { |item| item['reference_id'] == id }
  raise "missing publisher receipt #{id}" unless entry
  sources << entry.merge('reuse_manifest' => '../crt-termination/sources.json')
end

FileUtils.mkdir_p(File.join(ARCHIVE, 'microsoft'))
PUBLIC.each do |name, path|
  url = "https://raw.githubusercontent.com/MicrosoftDocs/cpp-docs/#{CPP_REV}/#{path}"
  bytes = fetch(url)
  File.binwrite(File.join(ARCHIVE, 'microsoft', name), bytes)
  canonical = name == 'signal-constants.md' ? 'signal-constants' : "reference/#{name.delete_suffix('.md')}"
  sources << { 'path' => "microsoft/#{name}", 'kind' => 'publisher documentation',
               'issuer' => 'MicrosoftDocs', 'revision' => CPP_REV, 'source_url' => url,
               'canonical_url' => "https://learn.microsoft.com/en-us/cpp/c-runtime-library/#{canonical}?view=msvc-170",
               'retrieved' => EXIT_DATE, 'normalization' => 'None; exact raw Markdown bytes',
               'license' => 'CC-BY-4.0 prose; MIT code samples; reused license inputs retained',
               'sha256' => Digest::SHA256.hexdigest(bytes), 'bytes' => bytes.bytesize }
end
entries, metadata = sdk_directory
raise 'changed SDK directory' unless metadata == parent.fetch('microsoft_sdk_package')
inspection = Dir.mktmpdir('rax-crt-exit-sdk.')
NEW_MEMBERS.each do |id, member|
  entry = entries.fetch(member)
  bytes = sdk_member(entry)
  File.binwrite(File.join(inspection, File.basename(id)), bytes)
  sources << { 'reference_id' => id, 'kind' => 'publisher SDK source/header receipt',
               'issuer' => 'Microsoft Corporation', 'revision' => 'SDK 10.0.26100.0; NuGet 10.0.26100.1',
               'source_url' => SDK_URL, 'sdk_zip_member' => entry, 'retrieved' => EXIT_DATE,
               'normalization' => 'None; exact uncompressed ZIP member bytes',
               'retention' => 'Temporary inspection only; proprietary raw bytes excluded from repository',
               'license' => 'Publisher copyright retained in temporary input; blanket source redistribution permission unknown',
               'sha256' => Digest::SHA256.hexdigest(bytes), 'bytes' => bytes.bytesize }
end
FileUtils.mkdir_p(File.join(ARCHIVE, 'symbols'))
%w[x86 x64 arm64].each do |arch|
  member = "c/Redist/10.0.26100.0/ucrt/DLLs/#{arch}/ucrtbase.dll"
  entry = entries.fetch(member)
  bytes = sdk_member(entry)
  output, argv = export_observation(bytes)
  path = "symbols/microsoft-ucrtbase-#{arch}.txt"
  File.binwrite(File.join(ARCHIVE, path), output)
  sources << { 'path' => path, 'kind' => 'publisher DLL named-export observation; not native execution',
               'issuer' => 'Microsoft Corporation', 'revision' => 'SDK 10.0.26100.0; NuGet 10.0.26100.1',
               'source_url' => SDK_URL, 'command_argv' => argv, 'selection_regex' => EXPORT_PATTERN,
               'command_stdin_sdk_member' => entry, 'input_bytes' => bytes.bytesize,
               'input_sha256' => Digest::SHA256.hexdigest(bytes), 'retrieved' => EXIT_DATE,
               'binary_retention' => 'None; publisher DLL streamed to observer only',
               'sha256' => Digest::SHA256.hexdigest(output), 'bytes' => output.bytesize }
end
manifest = { 'schema' => 1, 'retrieved' => EXIT_DATE, 'baseline_head' => EXIT_BASELINE,
             'purpose' => 'Bounded UCRT termination and SIGABRT/SIGTERM provenance; not complete signal support',
             'microsoft_sdk_package' => metadata,
             'microsoft_sdk_full_package_digest' => parent.fetch('microsoft_sdk_full_package_digest').merge('reuse_manifest' => '../crt-termination/sources.json'),
             'nuget_signature_verification' => 'not performed',
             'native_windows_execution_oracle' => 'unknown', 'raw_sdk_source_committed' => false,
             'sdk_helper_sha256' => HELPER_SHA, 'parent_manifest_sha256' => PARENT_SHA,
             'acquisition_script_sha256' => Digest::SHA256.file(__FILE__).hexdigest,
             'tools' => parent.fetch('tools').select { |tool| %w[llvm-readobj curl ruby].include?(File.basename(tool.fetch('path'))) },
             'sources' => sources }
File.binwrite(File.join(ARCHIVE, 'sources.json'), JSON.pretty_generate(manifest) + "\n")
puts "Publisher source inspection: #{inspection}"
puts "Sources: #{sources.length}; retained bytes and publisher source receipts only"
