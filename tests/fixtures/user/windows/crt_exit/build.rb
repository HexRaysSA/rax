#!/usr/bin/env ruby
# Only this owned corpus is generated. All source edits remain hand-maintained.
require 'digest'
require 'fileutils'
require 'json'
require 'open3'
require 'tmpdir'
ROOT = File.expand_path(__dir__)
REPOSITORY = File.expand_path('../../../../..', ROOT)
TOOLS = {
  'clang' => ENV.fetch('CLANG_BIN', '/Users/int/local/bin/clang'),
  'linker' => ENV.fetch('LLD_LINK_BIN', '/Users/int/local/bin/lld-link'),
  'dlltool' => ENV.fetch('LLVM_DLLTOOL_BIN', '/Users/int/local/bin/llvm-dlltool'),
  'readobj' => ENV.fetch('LLVM_READOBJ_BIN', '/Users/int/local/bin/llvm-readobj')
}.freeze
MODES = [
  ['full_exit', 17, 'TBCAD', true], ['quick_exit', 18, 'RSQD', true],
  ['minimal_exit', 19, 'D', true], ['minimal_Exit', 20, 'D', true],
  ['raw_exit_process', 21, 'D', true], ['forced_process', 22, '', false],
  ['cexit_repeat', 0, 'TBCATVD', true], ['c_exit', 0, 'VD', true],
  ['duplicate_tls_custom', 23, 'H', false], ['duplicate_tls_default', 0xc0000409, '', false],
  ['terminate_return', 3, 'HD', true], ['terminate_fault', 3, 'HD', true],
  ['abort_custom', 3, 'SD', true], ['abort_ignore', 3, 'D', true],
  ['signal_roundtrip', 0, 'ABZIVD', true], ['signalterm_default', 3, 'D', true],
  ['cpp_escaped', 24, 'TXH', false], ['noncpp_escaped', 25, 'TXO', false],
  ['terminate_inner', 3, 'HIRD', true], ['cpp_inner', 26, 'TXIRAD', true],
  ['cpp_unwind', 24, 'TXUH', false]
].freeze
def run(argv, **options)
  output, status = Open3.capture2e(*argv, **options)
  raise "failed #{argv.inspect}\n#{output}" unless status.success?
  output
end
def sha(path)
  Digest::SHA256.file(path).hexdigest
end
tools = TOOLS.map do |name, path|
  { 'name' => name, 'path' => path, 'sha256' => sha(path),
    'version' => name == 'dlltool' ? 'No version flag; executable hash pins identity' : run([path, '--version']).strip }
end
fixtures = []
cases = []
producer = []
Dir.mktmpdir('rax-crt-exit-build.') do |temporary|
  %w[x86 x64 arm64].each do |arch|
    target, machine, dllmachine, suffix, extra = case arch
      when 'x86' then ['i686-pc-windows-msvc', 'x86', 'i386', '-x86', []]
      when 'x64' then ['x86_64-pc-windows-msvc', 'x64', 'i386:x86-64', '', []]
      when 'arm64' then ['aarch64-pc-windows-msvc', 'arm64', 'arm64', '', ['-mgeneral-regs-only', '-ffixed-x18']]
    end
    compile_base = [TOOLS.fetch('clang'), "--target=#{target}", '-Oz', '-ffreestanding', '-fno-builtin',
      '-fno-stack-protector', '-fno-ident', '-fno-vectorize', '-fno-slp-vectorize',
      '-funwind-tables', '-fasynchronous-unwind-tables',
      "-ffile-prefix-map=#{ROOT}=.", "-ffile-prefix-map=#{REPOSITORY}=repository", *extra]
    objects = %w[graph.c scopes.S companion.c].to_h do |source|
      object = File.join(temporary, source + '.obj')
      compile = [*compile_base, '-c', File.join(ROOT, 'src', source), '-o', object]
      run(compile)
      [source, object]
    end
    kernel_library = File.join(temporary, 'kernel32.lib')
    run([TOOLS.fetch('dlltool'), '-m', dllmachine, '-k', '-d', File.join(ROOT, "src/kernel32#{suffix}.def"), '-l', kernel_library])
    %w[ucrtbase apiset].each do |binding|
      runtime_dll = binding == 'apiset' ? 'api-ms-win-crt-runtime-l1-1-0.dll' : 'ucrtbase.dll'
      stdio_dll = binding == 'apiset' ? 'api-ms-win-crt-stdio-l1-1-0.dll' : 'ucrtbase.dll'
      runtime_library = File.join(temporary, 'runtime.lib')
      stdio_library = File.join(temporary, 'stdio.lib')
      run([TOOLS.fetch('dlltool'), '-m', dllmachine, '-D', runtime_dll, '-d', File.join(ROOT, 'src/runtime.def'), '-l', runtime_library])
      run([TOOLS.fetch('dlltool'), '-m', dllmachine, '-D', stdio_dll, '-d', File.join(ROOT, 'src/stdio.def'), '-l', stdio_library])
      %w[graph companion].each do |role|
        extension = role == 'graph' ? 'exe' : 'dll'
        path = "bin/#{arch}/#{binding}/#{role}.#{extension}"
        absolute = File.join(ROOT, path)
        FileUtils.mkdir_p(File.dirname(absolute))
        link = [TOOLS.fetch('linker'), "/machine:#{machine}", '/nodefaultlib', '/timestamp:0', '/dynamicbase',
          '/nxcompat', '/safeseh:no', '/subsystem:console', '/stack:1048576,4096', '/heap:1048576,4096',
          "/out:#{absolute}"]
        if role == 'graph'
          link.concat(['/entry:entry', objects.fetch('graph.c'), objects.fetch('scopes.S'), kernel_library, runtime_library, stdio_library])
        else
          link.concat(['/dll', '/entry:DllMain', '/base:0x180000000', objects.fetch('companion.c'), kernel_library])
          link << '/base:0x68000000' if arch == 'x86'
          link << "/implib:#{File.join(temporary, 'companion.lib')}"
        end
        run(link)
        observation_path = "observations/#{arch}-#{binding}-#{role}.txt"
        observation = run([TOOLS.fetch('readobj'), '--file-headers', '--coff-imports', '--coff-exports', '--unwind', '-'], stdin_data: File.binread(absolute))
        FileUtils.mkdir_p(File.join(ROOT, 'observations'))
        File.binwrite(File.join(ROOT, observation_path), observation)
        imports = observation.scan(/Import \{\n(.*?)\n\}/m).map do |block|
          text = block.first
          { 'dll' => text[/^  Name: (.+)$/, 1], 'symbols' => text.scan(/^  Symbol: ([^ ]+)/).flatten.sort }
        end.sort_by { |entry| entry.fetch('dll') }
        if role == 'graph'
          expected_runtime = File.readlines(File.join(ROOT, 'src/runtime.def')).drop(2).map(&:strip).reject(&:empty?).sort
          expected_stdio = File.readlines(File.join(ROOT, 'src/stdio.def')).drop(2).map(&:strip).reject(&:empty?).sort
          expected = binding == 'apiset' ? { runtime_dll => expected_runtime, stdio_dll => expected_stdio } : { runtime_dll => (expected_runtime + expected_stdio).sort }
          expected.each { |dll, symbols| raise "wrong exact CRT IAT #{arch}/#{binding}/#{dll}" unless imports.find { |i| i['dll'] == dll }&.fetch('symbols') == symbols }
          raise 'unexpected helper DLL import' unless imports.map { |i| i['dll'] }.sort == ['kernel32.dll', *expected.keys].sort
          raise 'missing selected Win64 guest scope handler metadata' if arch != 'x86' && !observation.include?('ExceptionHandler')
        else
          raise 'companion has a hidden CRT dependency' unless imports.map { |i| i['dll'] } == ['kernel32.dll']
          raise 'missing exact companion configure export' unless observation.scan(/^  Name: (configure)$/).flatten == ['configure']
        end
        fixtures << { 'arch' => arch, 'binding' => binding, 'role' => role, 'path' => path,
          'sha256' => sha(absolute), 'bytes' => File.size(absolute), 'imports' => imports,
          'iat_path' => observation_path, 'iat_sha256' => sha(File.join(ROOT, observation_path)) }
      end
      MODES.each_with_index do |(name, status, stdout, detach), mode|
        cases << { 'arch' => arch, 'binding' => binding, 'mode' => mode, 'name' => name,
          'image_path' => "bin/#{arch}/#{binding}/graph.exe", 'companion_path' => "bin/#{arch}/#{binding}/companion.dll",
          'command_line' => "graph.exe #{mode}", 'expected_status' => status, 'expected_shell_exit' => status & 255,
          'expected_stdout' => stdout, 'expected_files' => { 'pending.bin' => detach ? 'B' : '' },
          'expected_detach' => detach, 'oracle' => 'Independent literals; SDK source profile; native Windows execution unknown' }
      end
      producer << { 'arch' => arch, 'binding' => binding, 'target' => target, 'machine' => machine,
        'compile_flags' => compile_base.drop(1).map { |a| a.gsub(ROOT, 'FIXTURE_ROOT').gsub(REPOSITORY, 'REPOSITORY') },
        'compile_inputs' => %w[src/graph.c src/scopes.S src/companion.c],
        'import_definition_inputs' => ["src/kernel32#{suffix}.def", 'src/runtime.def', 'src/stdio.def'],
        'compiler_command_recipe' => ['clang', "--target=#{target}", 'compile_flags...', '-c', 'FIXTURE_ROOT/compile_input', '-o', 'TEMPORARY/input.obj'],
        'observer_command' => ['llvm-readobj', '--file-headers', '--coff-imports', '--coff-exports', '--unwind', '-'],
        'link_flags' => ['/nodefaultlib', '/timestamp:0', '/dynamicbase', '/nxcompat', '/safeseh:no', '/stack:1048576,4096', '/heap:1048576,4096'],
        'runtime_dll' => runtime_dll, 'stdio_dll' => stdio_dll,
        'guest_scope_metadata' => arch == 'x86' ? 'FS:[0] explicit registration; SafeSEH checking disabled in fixture image' : 'LLVM .seh_handler except metadata; no __C_specific_handler' }
    end
  end
end
source_paths = %w[build.rb baseline.rb README.md src/common.h src/graph.c src/companion.c src/scopes.S src/runtime.def src/stdio.def src/kernel32.def src/kernel32-x86.def]
sources = source_paths.map { |path| { 'path' => path, 'sha256' => sha(File.join(ROOT, path)), 'bytes' => File.size(File.join(ROOT, path)) } }
manifest = { 'schema' => 1, 'source_baseline' => '02f28dbb4b6cc51e394987b7784ca34de965e2f5',
  'purpose' => 'Custom-entry retail dynamic UCRT termination, software signal and guest SEH crossing witnesses; no ordinary CRT startup',
  'native_windows_oracle' => 'unknown; no recorded native execution', 'slices' => [1, 4096],
  'physical_pe_count' => 12, 'semantic_case_count' => 126, 'required_execution_count' => 252,
  'primary_sources_path' => '../../../../../docs/specifications/windows/crt-exit/sources.json',
  'primary_sources_sha256' => Digest::SHA256.file(File.join(REPOSITORY, 'docs/specifications/windows/crt-exit/sources.json')).hexdigest,
  'tools' => tools, 'producers' => producer, 'sources' => sources, 'fixtures' => fixtures, 'cases' => cases }
File.binwrite(File.join(ROOT, 'manifest.json'), JSON.pretty_generate(manifest) + "\n")
puts "Generated #{fixtures.length} PEs, #{cases.length} independent mode cells; native Windows execution unknown"
