#!/usr/bin/env ruby
# Generate only owned custom-entry fixtures and their exact producer/IAT receipts.
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
}
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
programs = { 'register_zero' => ['registration.c', 0, "registered\n"],
             'register_65' => ['registration.c', 65, "registered\n"],
             'register_1057' => ['registration.c', 1057, "registered\n"],
             'explicit' => ['explicit.c', nil, "explicit\n"],
             'concurrent' => ['concurrent.c', nil, "concurrent\n"] }
Dir.mktmpdir('rax-crt-termination-build.') do |temporary|
  %w[x86 x64 arm64].each do |arch|
    target, machine, dllmachine, suffix, extra = case arch
      when 'x86' then ['i686-pc-windows-msvc', 'x86', 'i386', '-x86', []]
      when 'x64' then ['x86_64-pc-windows-msvc', 'x64', 'i386:x86-64', '', []]
      when 'arm64' then ['aarch64-pc-windows-msvc', 'arm64', 'arm64', '', ['-mgeneral-regs-only', '-ffixed-x18']]
    end
    kernel_library = File.join(temporary, 'kernel32.lib')
    run([TOOLS.fetch('dlltool'), '-m', dllmachine, '-k', '-d', File.join(ROOT, "src/kernel32#{suffix}.def"), '-l', kernel_library])
    %w[ucrtbase apiset].each do |binding|
      dll = binding == 'apiset' ? 'api-ms-win-crt-runtime-l1-1-0.dll' : 'ucrtbase.dll'
      runtime_library = File.join(temporary, 'runtime.lib')
      run([TOOLS.fetch('dlltool'), '-m', dllmachine, '-D', dll, '-d', File.join(ROOT, 'src/runtime.def'), '-l', runtime_library])
      programs.each do |program, (source, count, stdout)|
        object = File.join(temporary, 'program.obj')
        path = "bin/#{arch}/#{binding}/#{program}.exe"
        absolute = File.join(ROOT, path)
        FileUtils.mkdir_p(File.dirname(absolute))
        compile = [TOOLS.fetch('clang'), "--target=#{target}", '-Oz', '-ffreestanding', '-fno-builtin',
                   '-fno-stack-protector', '-fno-ident', '-fno-vectorize', '-fno-slp-vectorize',
                   '-fno-asynchronous-unwind-tables', '-fno-unwind-tables',
                   "-ffile-prefix-map=#{ROOT}=.", "-ffile-prefix-map=#{REPOSITORY}=repository", *extra]
        compile << "-DREGISTRATIONS=#{count}" if count
        compile.concat(['-c', File.join(ROOT, "src/#{source}"), '-o', object])
        run(compile)
        link = [TOOLS.fetch('linker'), "/machine:#{machine}", '/nodefaultlib', '/timestamp:0', '/dynamicbase',
                '/nxcompat', '/entry:entry', '/subsystem:console', '/stack:1048576,4096', '/heap:1048576,4096',
                "/out:#{absolute}", object, kernel_library, runtime_library]
        run(link)
        observation_path = "observations/#{arch}-#{binding}-#{program}.txt"
        observation = run([TOOLS.fetch('readobj'), '--file-headers', '--coff-imports', '-'], stdin_data: File.binread(absolute))
        FileUtils.mkdir_p(File.join(ROOT, 'observations'))
        File.binwrite(File.join(ROOT, observation_path), observation)
        imports = observation.scan(/Import \{\n(.*?)\n\}/m).map do |block|
          text = block.first
          { 'dll' => text[/^  Name: (.+)$/, 1], 'symbols' => text.scan(/^  Symbol: ([^ ]+)/).flatten.sort }
        end.sort_by { |entry| entry.fetch('dll') }
        runtime = imports.find { |entry| entry.fetch('dll') == dll }
        raise 'incorrect runtime IAT' unless runtime && runtime.fetch('symbols').include?('_crt_atexit') && runtime.fetch('symbols').include?('_crt_at_quick_exit')
        raise 'unexpected DLL in IAT' unless imports.map { |entry| entry.fetch('dll') }.sort == ['kernel32.dll', dll].sort
        fixture = { 'arch' => arch, 'binding' => binding, 'program' => program, 'path' => path,
                    'sha256' => sha(absolute), 'bytes' => File.size(absolute), 'expected_exit' => 0,
                    'expected_stdout' => stdout, 'role' => 'custom-entry; no CRT startup object',
                    'imports' => imports, 'iat_path' => observation_path, 'iat_sha256' => sha(File.join(ROOT, observation_path)) }
        fixture['registrations_per_queue'] = count unless count.nil?
        fixtures << fixture
      end
    end
  end
end
sources = %w[build.rb baseline.rb README.md src/common.h src/registration.c src/explicit.c src/concurrent.c src/runtime.def src/kernel32.def src/kernel32-x86.def].map do |path|
  { 'path' => path, 'sha256' => sha(File.join(ROOT, path)), 'bytes' => File.size(File.join(ROOT, path)) }
end
manifest = { 'schema' => 1, 'source_baseline' => '06e90d4bb41e0390a877819ed41ed98e369558a3',
             'purpose' => 'Genuine UCRT runtime-global registration and recursive shared exit-lock witnesses',
             'native_windows_oracle' => 'unknown; no recorded native execution',
             'producer' => 'Clang custom-entry C objects; llvm-dlltool definitions validated against primary Microsoft UCRT exports; LLD /nodefaultlib /timestamp:0',
             'tools' => tools, 'sources' => sources, 'fixtures' => fixtures }
File.binwrite(File.join(ROOT, 'manifest.json'), JSON.pretty_generate(manifest) + "\n")
puts "Generated #{fixtures.length} genuine-import custom-entry PEs; native Windows execution unknown"
