#!/usr/bin/env ruby
# Generate only this owned corpus. No engine, dependency, or ordinary CRT build.
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
  'readobj' => ENV.fetch('LLVM_READOBJ_BIN', '/Users/int/local/bin/llvm-readobj'),
  'objdump' => ENV.fetch('LLVM_OBJDUMP_BIN', '/Users/int/local/bin/llvm-objdump')
}.freeze
MODES = [
  ['control', 0, "control\n", nil],
  ['app_extrema_shared', 0, "app\n", '_query_app_type'],
  ['locale_valid', 0, "locale\n", '_configthreadlocale'],
  ['locale_invalid_return', 0, "invalid\n", '_configthreadlocale'],
  ['math_no_eager_call', 0, "math\n", '__setusermatherr'],
  ['fp_raw_and_scalar', 0, "fp\n", '_fpreset'],
  ['saved_context', 0, "context\n", '__pxcptinfoptrs'],
  ['locale_thread_isolation', 0, "threads\n", '_configthreadlocale'],
  ['locale_invalid_default', 0xc0000409, '', '_configthreadlocale'],
  ['exception_pointer_cell', 0, "cell\n", '__pxcptinfoptrs'],
  ['private_fp_instrumentation_control', 0, "fp-control\n", nil]
].freeze

def run(argv, **options)
  output, status = Open3.capture2e(*argv, **options)
  raise "failed #{argv.inspect}\n#{output}" unless status.success?
  output
end
def sha(path)
  Digest::SHA256.file(path).hexdigest
end
def symbols(path)
  File.readlines(path).drop(2).map(&:strip).reject(&:empty?).sort
end

tools = TOOLS.map do |name, path|
  { 'name' => name, 'path' => path, 'sha256' => sha(path),
    'version' => name == 'dlltool' ? 'No version flag; executable hash pins identity' : run([path, '--version']).strip }
end
fixtures = []
cases = []
producers = []
Dir.mktmpdir('rax-crt-bootstrap-build.') do |temporary|
  %w[x86 x64 arm64].each do |arch|
    target, machine, dllmachine, suffix, extra = case arch
      when 'x86' then ['i686-pc-windows-msvc', 'x86', 'i386', '-x86', ['-mno-sse', '-mno-sse2', '-mno-mmx']]
      when 'x64' then ['x86_64-pc-windows-msvc', 'x64', 'i386:x86-64', '', ['-mno-sse', '-mno-sse2', '-mno-mmx']]
      when 'arm64' then ['aarch64-pc-windows-msvc', 'arm64', 'arm64', '', ['-mgeneral-regs-only', '-ffixed-x18']]
    end
    compile_base = [TOOLS.fetch('clang'), "--target=#{target}", '-Oz', '-ffreestanding', '-fno-builtin',
      '-fno-stack-protector', '-fno-ident', '-fno-vectorize', '-fno-slp-vectorize',
      '-fno-asynchronous-unwind-tables', '-fno-unwind-tables',
      "-ffile-prefix-map=#{ROOT}=.", "-ffile-prefix-map=#{REPOSITORY}=repository"]
    objects = %w[graph.c fp.S].map do |source|
      object = File.join(temporary, source + '.obj')
      # The C compiler may not use floating-point/vector registers before or
      # after assembly snapshots. Assembly deliberately accesses the raw state.
      run([*compile_base, *(source.end_with?('.c') ? extra : []), '-c', File.join(ROOT, 'src', source), '-o', object])
      object
    end
    kernel_library = File.join(temporary, 'kernel32.lib')
    run([TOOLS.fetch('dlltool'), '-m', dllmachine, '-k', '-d', File.join(ROOT, "src/kernel32#{suffix}.def"), '-l', kernel_library])
    %w[ucrtbase apiset].each do |binding|
      dlls = {
        'runtime' => binding == 'apiset' ? 'api-ms-win-crt-runtime-l1-1-0.dll' : 'ucrtbase.dll',
        'locale' => binding == 'apiset' ? 'api-ms-win-crt-locale-l1-1-0.dll' : 'ucrtbase.dll',
        'math' => binding == 'apiset' ? 'api-ms-win-crt-math-l1-1-0.dll' : 'ucrtbase.dll'
      }
      libraries = dlls.map do |category, dll|
        path = File.join(temporary, category + '.lib')
        run([TOOLS.fetch('dlltool'), '-m', dllmachine, '-D', dll, '-d', File.join(ROOT, "src/#{category}.def"), '-l', path])
        path
      end
      path = "bin/#{arch}/#{binding}/graph.exe"
      absolute = File.join(ROOT, path)
      FileUtils.mkdir_p(File.dirname(absolute))
      run([TOOLS.fetch('linker'), "/machine:#{machine}", '/nodefaultlib', '/timestamp:0', '/dynamicbase',
        '/nxcompat', '/safeseh:no', '/entry:entry', '/subsystem:console', '/stack:1048576,4096', '/heap:1048576,4096',
        "/out:#{absolute}", *objects, kernel_library, *libraries])
      observation_path = "observations/#{arch}-#{binding}-iat.txt"
      observation = run([TOOLS.fetch('readobj'), '--file-headers', '--coff-imports', '-'], stdin_data: File.binread(absolute))
      FileUtils.mkdir_p(File.join(ROOT, 'observations'))
      File.binwrite(File.join(ROOT, observation_path), observation)
      disassembly_path = "observations/#{arch}-#{binding}-instructions.txt"
      disassembly = run([TOOLS.fetch('objdump'), '--disassemble', '--print-imm-hex', '-'], stdin_data: File.binread(absolute))
      File.binwrite(File.join(ROOT, disassembly_path), disassembly)
      imports = observation.scan(/Import \{\n(.*?)\n\}/m).map do |block|
        text = block.first
        { 'dll' => text[/^  Name: (.+)$/, 1], 'symbols' => text.scan(/^  Symbol: ([^ ]+)/).flatten.sort }
      end.sort_by { |entry| entry.fetch('dll') }
      expected = {}
      dlls.each { |category, dll| (expected[dll] ||= []).concat(symbols(File.join(ROOT, "src/#{category}.def"))) }
      expected.transform_values!(&:sort)
      expected.each { |dll, names| raise "wrong exact CRT IAT #{arch}/#{binding}/#{dll}" unless imports.find { |i| i['dll'] == dll }&.fetch('symbols') == names }
      raise 'unexpected helper DLL import' unless imports.map { |i| i['dll'] }.sort == ['kernel32.dll', *expected.keys].sort
      fixtures << { 'arch' => arch, 'binding' => binding, 'path' => path, 'sha256' => sha(absolute),
        'bytes' => File.size(absolute), 'imports' => imports, 'iat_path' => observation_path,
        'iat_sha256' => sha(File.join(ROOT, observation_path)), 'instructions_path' => disassembly_path,
        'instructions_sha256' => sha(File.join(ROOT, disassembly_path)) }
      MODES.each_with_index do |(name, status, stdout, absent), mode|
        cases << { 'arch' => arch, 'binding' => binding, 'mode' => mode, 'name' => name,
          'image_path' => path, 'command_line' => "graph.exe #{mode}", 'expected_status' => status,
          'expected_shell_exit' => status & 255, 'expected_stdout' => stdout,
          'baseline_missing_export' => absent && "ucrtbase.dll!#{absent}",
          'oracle' => 'Independent assertions from pinned SDK/publisher contracts; no native Windows execution' }
      end
      producers << { 'arch' => arch, 'binding' => binding, 'target' => target, 'machine' => machine,
        'compile_flags' => compile_base.drop(1).map { |a| a.gsub(ROOT, 'FIXTURE_ROOT').gsub(REPOSITORY, 'REPOSITORY') },
        'c_register_restrictions' => extra, 'assembly_abi' => 'Manually preserved caller nonvolatile registers and complete original FP state; no compiler instructions between raw snapshots',
        'compile_inputs' => ['src/graph.c', 'src/fp.S'], 'import_definition_inputs' => ["src/kernel32#{suffix}.def", 'src/runtime.def', 'src/locale.def', 'src/math.def'],
        'link_flags' => ['/nodefaultlib', '/timestamp:0', '/dynamicbase', '/nxcompat', '/safeseh:no', '/entry:entry', '/stack:1048576,4096', '/heap:1048576,4096'],
        'import_families' => dlls, 'observer_command' => ['llvm-readobj', '--file-headers', '--coff-imports', '-'],
        'instruction_observer_command' => ['llvm-objdump', '--disassemble', '--print-imm-hex', '-'] }
    end
  end
end
source_paths = %w[build.rb baseline.rb verify_rebuild.rb README.md src/common.h src/graph.c src/fp.S src/runtime.def src/locale.def src/math.def src/kernel32.def src/kernel32-x86.def]
sources = source_paths.map { |path| { 'path' => path, 'sha256' => sha(File.join(ROOT, path)), 'bytes' => File.size(File.join(ROOT, path)) } }
manifest = { 'schema' => 1, 'source_baseline' => '9bc8ccdca85a5b0c9c74a7c446c85194efdc780d',
  'purpose' => 'Custom-entry genuine UCRT startup policy and exact ABI-specific floating-point reset witnesses; no ordinary CRT startup',
  'native_windows_oracle' => 'unknown; no recorded native execution', 'slices' => [1, 4096],
  'rebuild_receipt_path' => 'rebuild.json',
  'physical_pe_count' => 6, 'semantic_case_count' => cases.length, 'required_execution_count' => cases.length * 2,
  'primary_sources_path' => '../../../../../docs/specifications/windows/crt-bootstrap/sources.json',
  'primary_sources_sha256' => sha(File.join(REPOSITORY, 'docs/specifications/windows/crt-bootstrap/sources.json')),
  'tools' => tools, 'producers' => producers, 'sources' => sources, 'fixtures' => fixtures, 'cases' => cases }
File.binwrite(File.join(ROOT, 'manifest.json'), JSON.pretty_generate(manifest) + "\n")
puts "Generated #{fixtures.length} PEs, #{cases.length} independent mode cells; native Windows execution unknown"
