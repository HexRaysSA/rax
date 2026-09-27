#!/usr/bin/env ruby
# Observe preserved pre-feature CLI, with exact isolated immutable guest inputs.
require 'digest'
require 'json'
require 'open3'
require 'tmpdir'
require 'timeout'
ROOT = File.expand_path(__dir__)
CLI_SHA = 'b3e53f095c865ebc4435f1ac1cd71739ea4fc8c95097d92f0f693b43fb70fcaa'
cli = File.realpath(ARGV.fetch(0))
raise 'wrong preserved CLI bytes' unless Digest::SHA256.file(cli).hexdigest == CLI_SHA
manifest_bytes = File.binread(File.join(ROOT, 'manifest.json'))
manifest = JSON.parse(manifest_bytes)
manifest.fetch('sources').each { |s| raise "changed source #{s['path']}" unless Digest::SHA256.file(File.join(ROOT, s.fetch('path'))).hexdigest == s.fetch('sha256') }
receipt = { 'schema' => 1, 'source_baseline' => manifest.fetch('source_baseline'), 'executable' => cli,
  'executable_sha256' => CLI_SHA, 'fixture_manifest_sha256' => Digest::SHA256.hexdigest(manifest_bytes),
  'seed' => 1, 'arena_bytes' => 67_108_864, 'watchdog_seconds' => 30, 'environment' => { 'RAX_NO_JIT' => '1' },
  'purpose' => 'Observed pre-feature import failures and raw normal-ExitProcess flush mismatch; no native oracle', 'runs' => [] }
manifest.fetch('cases').each do |c|
  [1, 4096].each do |slice|
    Dir.mktmpdir('rax-crt-exit-baseline.') do |temporary|
      inputs = [c.fetch('image_path'), c.fetch('companion_path')].map do |path|
        fixture = manifest.fetch('fixtures').find { |f| f.fetch('path') == path }
        bytes = File.binread(File.join(ROOT, path))
        raise "changed image #{path}" unless Digest::SHA256.hexdigest(bytes) == fixture.fetch('sha256')
        target = File.join(temporary, File.basename(path))
        File.binwrite(target, bytes)
        [target, bytes, fixture.fetch('sha256')]
      end
      argv = [cli, '--os', 'windows', '--memory', '64M', '--slice', slice.to_s, '--seed', '1',
        '--drive', "C=#{temporary}", '--cwd', 'C:\\', '--command-line', c.fetch('command_line'), inputs.first.first]
      stdout = stderr = nil
      status = nil
      timeout = false
      Open3.popen3({ 'RAX_NO_JIT' => '1' }, *argv) do |stdin, out, err, wait|
        stdin.close
        readers = [Thread.new { out.read }, Thread.new { err.read }]
        begin
          Timeout.timeout(30) { status = wait.value; stdout, stderr = readers.map(&:value) }
        rescue Timeout::Error
          Process.kill('KILL', wait.pid)
          status = wait.value
          stdout, stderr = readers.map(&:value)
          timeout = true
        end
      end
      inputs.each { |path, bytes, _| raise 'guest changed immutable input' unless File.binread(path) == bytes }
      path = File.join(temporary, 'pending.bin')
      files = { 'pending.bin' => File.file?(path) ? File.binread(path) : nil }
      missing = stderr[/unimplemented Windows export: ([^!]+![^ ]+) at /, 1]
      observed = timeout ? 'watchdog expired; cause unknown' : missing ? 'unimplemented export' : 'observed execution'
      if c.fetch('mode') == 4
        raise "raw ExitProcess baseline did not expose old flush mismatch #{c['arch']}/#{c['binding']}: #{status.inspect} #{stdout.inspect} #{files.inspect} #{stderr}" unless !timeout && status.exitstatus == 21 && stdout == 'D' && files == { 'pending.bin' => '' }
        observed = 'normal DLL detach observed; pending UCRT output not flushed'
      elsif c.fetch('mode') == 5
        raise 'incorrect forced baseline observation' unless !timeout && status.exitstatus == 22 && stdout.empty? && files == { 'pending.bin' => '' } && missing.nil?
      else
        expected = case c.fetch('mode')
          when 0, 1, 2, 3, 6, 7, 9 then 'ucrtbase.dll!_register_thread_local_exe_atexit_callback'
          when 8, 10, 11, 16, 17, 18, 19, 20 then 'ucrtbase.dll!set_terminate'
          when 12, 13, 14, 15 then 'ucrtbase.dll!signal'
        end
        raise 'unexpected preserved import-failure observation' unless !timeout && status.exitstatus == 125 && stdout.empty? && files == { 'pending.bin' => '' } && missing == expected
      end
      receipt.fetch('runs') << { 'arch' => c.fetch('arch'), 'binding' => c.fetch('binding'),
        'mode' => c.fetch('mode'), 'name' => c.fetch('name'), 'path' => c.fetch('image_path'),
        'input_sha256' => inputs.first.last, 'companion_sha256' => inputs.last.last,
        'slice_instructions' => slice, 'arguments' => argv.drop(1).map { |a| a.gsub(temporary, 'ISOLATED_INPUT_DIRECTORY') },
        'shell_exit' => status.exitstatus, 'signal' => status.termsig, 'watchdog_expired' => timeout,
        'stdout' => stdout, 'stderr' => stderr.gsub(temporary, 'ISOLATED_INPUT_DIRECTORY'),
        'files' => files, 'missing_export' => missing, 'observation' => observed }
    end
  end
end
raise 'incorrect baseline count' unless receipt.fetch('runs').length == 252
raise 'incorrect baseline matrix' unless receipt.fetch('runs').map { |r| [r['arch'], r['binding'], r['mode'], r['slice_instructions']] }.uniq.size == 252
File.binwrite(File.join(ROOT, 'baseline.json'), JSON.pretty_generate(receipt) + "\n")
puts "Observed #{receipt.fetch('runs').length} preserved-CLI executions; no native Windows execution"
