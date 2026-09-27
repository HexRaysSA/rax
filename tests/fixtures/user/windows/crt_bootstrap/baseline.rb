#!/usr/bin/env ruby
# Observe preserved pre-feature RAX. Success controls are distinct from missing APIs.
require 'digest'
require 'json'
require 'open3'
require 'tmpdir'
require 'timeout'
ROOT = File.expand_path(__dir__)
CLI_SHA = '7823ddd8837f729dc62f2f3af02fe4bc31d65c571e0140a04cdb7c5606179612'
cli = File.realpath(ARGV.fetch(0))
raise 'wrong preserved CLI bytes' unless Digest::SHA256.file(cli).hexdigest == CLI_SHA
bytes = File.binread(File.join(ROOT, 'manifest.json'))
manifest = JSON.parse(bytes)
manifest.fetch('sources').each { |s| raise "changed source #{s['path']}" unless Digest::SHA256.file(File.join(ROOT, s.fetch('path'))).hexdigest == s.fetch('sha256') }
receipt = { 'schema' => 1, 'source_baseline' => manifest.fetch('source_baseline'), 'executable' => cli,
  'executable_sha256' => CLI_SHA, 'fixture_manifest_sha256' => Digest::SHA256.hexdigest(bytes),
  'seed' => 1, 'arena_bytes' => 67_108_864, 'watchdog_seconds' => 30,
  'environment' => { 'RAX_NO_JIT' => '1' }, 'guest_environment' => 'cleared by --clear-env',
  'purpose' => 'Observed pre-feature missing named exports plus independent raw ExitProcess controls; not a native oracle', 'runs' => [] }
manifest.fetch('cases').each do |c|
  manifest.fetch('slices').each do |slice|
    Dir.mktmpdir('rax-crt-bootstrap-baseline.') do |temporary|
      fixture = manifest.fetch('fixtures').find { |f| f.fetch('path') == c.fetch('image_path') }
      image = File.binread(File.join(ROOT, fixture.fetch('path')))
      raise 'changed PE bytes' unless Digest::SHA256.hexdigest(image) == fixture.fetch('sha256')
      path = File.join(temporary, 'graph.exe')
      File.binwrite(path, image)
      argv = [cli, '--os', 'windows', '--memory', '64M', '--slice', slice.to_s, '--seed', '1', '--clear-env',
        '--drive', "C=#{temporary}", '--cwd', 'C:\\', '--command-line', c.fetch('command_line'), path]
      stdout = stderr = status = nil
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
      raise 'guest changed immutable input' unless File.binread(path) == image
      missing = stderr[/unimplemented Windows export: ([^!]+![^ ]+) at /, 1]
      expected = c.fetch('baseline_missing_export')
      if expected
        raise "unexpected missing-export baseline #{c['arch']}/#{c['binding']}/#{c['mode']} #{status.inspect} #{stdout.inspect} #{stderr}" unless !timeout && status.exitstatus == 125 && stdout.empty? && missing == expected
        observation = 'observed absent export; execution stopped before postcondition'
      else
        raise 'independent control failed' unless !timeout && status.exitstatus == 0 && stdout == c.fetch('expected_stdout') && missing.nil?
        observation = c.fetch('mode') == 0 ? 'raw ExitProcess negative control succeeded without CRT bootstrap calls' : 'private ISA reset instrumentation succeeded without exported _fpreset call'
      end
      receipt.fetch('runs') << { 'arch' => c.fetch('arch'), 'binding' => c.fetch('binding'), 'mode' => c.fetch('mode'),
        'name' => c.fetch('name'), 'path' => c.fetch('image_path'), 'input_sha256' => fixture.fetch('sha256'),
        'slice_instructions' => slice, 'arguments' => argv.drop(1).map { |a| a.gsub(temporary, 'ISOLATED_INPUT_DIRECTORY') },
        'shell_exit' => status.exitstatus, 'signal' => status.termsig, 'watchdog_expired' => timeout,
        'stdout' => stdout, 'stderr' => stderr.gsub(temporary, 'ISOLATED_INPUT_DIRECTORY'),
        'missing_export' => missing, 'observation' => observation }
    end
  end
end
raise 'wrong execution count/matrix' unless receipt.fetch('runs').length == 132 && receipt.fetch('runs').map { |r| [r['arch'], r['binding'], r['mode'], r['slice_instructions']] }.uniq.length == 132
File.binwrite(File.join(ROOT, 'baseline.json'), JSON.pretty_generate(receipt) + "\n")
puts "Observed 132 pre-feature runs: 108 absent-export failures and 24 independent controls; no native Windows execution"
