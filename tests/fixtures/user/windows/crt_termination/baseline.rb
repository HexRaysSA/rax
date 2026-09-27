#!/usr/bin/env ruby
# Capture observed pre-feature RAX rejection; no compilation or native oracle.
require 'digest'
require 'json'
require 'open3'
require 'timeout'
ROOT = File.expand_path(__dir__)
cli = File.realpath(ARGV.fetch(0))
manifest_bytes = File.binread(File.join(ROOT, 'manifest.json'))
manifest = JSON.parse(manifest_bytes)
receipt = { 'schema' => 1, 'source_baseline' => manifest.fetch('source_baseline'),
            'executable' => cli, 'executable_sha256' => Digest::SHA256.file(cli).hexdigest,
            'fixture_manifest_sha256' => Digest::SHA256.hexdigest(manifest_bytes),
            'purpose' => 'Observed pre-feature global registrar import rejection; no native Windows oracle',
            'seed' => 1, 'arena_bytes' => 67_108_864, 'watchdog_seconds' => 30,
            'environment' => { 'RAX_NO_JIT' => '1' }, 'runs' => [] }
manifest.fetch('fixtures').each do |fixture|
  image = File.join(ROOT, fixture.fetch('path'))
  raise 'changed fixture' unless Digest::SHA256.file(image).hexdigest == fixture.fetch('sha256')
  [1, 4096].each do |slice|
    argv = [cli, '--os', 'windows', '--memory', '64M', '--slice', slice.to_s, '--seed', '1', image]
    stdout = stderr = nil
    status = nil
    Open3.popen3({ 'RAX_NO_JIT' => '1' }, *argv) do |stdin, out, err, wait|
      stdin.close
      readers = [Thread.new { out.read }, Thread.new { err.read }]
      begin
        Timeout.timeout(30) { status = wait.value; stdout, stderr = readers.map(&:value) }
      rescue Timeout::Error
        Process.kill('KILL', wait.pid)
        wait.value
        readers.each(&:join)
        raise "baseline watchdog expired #{fixture['path']} slice #{slice}"
      end
    end
    missing = stderr[/unimplemented Windows export: [^!]+!(_crt_atexit|_crt_at_quick_exit) at /, 1]
    raise "unexpected baseline #{fixture['path']} #{status.exitstatus}: #{stderr}" unless status.exitstatus == 125 && missing && stdout.empty?
    receipt.fetch('runs') << { 'path' => fixture.fetch('path'), 'arch' => fixture.fetch('arch'),
                              'binding' => fixture.fetch('binding'), 'input_sha256' => fixture.fetch('sha256'),
                              'slice_instructions' => slice, 'arguments' => argv.drop(1), 'shell_exit' => status.exitstatus,
                              'missing_export' => missing, 'stdout' => stdout, 'stderr' => stderr }
  end
end
raise 'wrong baseline count' unless receipt.fetch('runs').length == 60
File.binwrite(File.join(ROOT, 'baseline.json'), JSON.pretty_generate(receipt) + "\n")
puts '60 observed pre-feature global-registrar import failures; no timeout or native execution'
