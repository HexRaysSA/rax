#!/usr/bin/env ruby
# A second independent producer invocation, not relinking cached objects.
require 'digest'
require 'json'
require 'open3'
ROOT = File.expand_path(__dir__)
path = File.join(ROOT, 'manifest.json')
first = File.binread(path)
manifest = JSON.parse(first)
inputs = manifest.fetch('sources') + manifest.fetch('fixtures').flat_map do |f|
  [{ 'path' => f.fetch('path'), 'sha256' => f.fetch('sha256') },
   { 'path' => f.fetch('iat_path'), 'sha256' => f.fetch('iat_sha256') },
   { 'path' => f.fetch('instructions_path'), 'sha256' => f.fetch('instructions_sha256') }]
end
inputs.each { |f| raise "first build hash mismatch #{f['path']}" unless Digest::SHA256.file(File.join(ROOT, f.fetch('path'))).hexdigest == f.fetch('sha256') }
output, status = Open3.capture2e('ruby', File.join(ROOT, 'build.rb'))
raise "second build failed #{output}" unless status.success?
raise 'repeated complete manifest differs' unless File.binread(path) == first
inputs.each { |f| raise "second build differs #{f['path']}" unless Digest::SHA256.file(File.join(ROOT, f.fetch('path'))).hexdigest == f.fetch('sha256') }
receipt = { 'schema' => 1, 'kind' => 'Two complete independent producer invocations; temporary C/assembly objects recreated',
  'manifest_sha256' => Digest::SHA256.hexdigest(first), 'physical_pe_count' => manifest.fetch('fixtures').length,
  'pe_bytes' => manifest.fetch('fixtures').sum { |f| f.fetch('bytes') }, 'verified_inputs' => inputs,
  'second_build_exit' => status.exitstatus, 'second_build_output' => output,
  'native_windows_oracle' => 'unknown; producer repeatability only' }
File.binwrite(File.join(ROOT, 'rebuild.json'), JSON.pretty_generate(receipt) + "\n")
puts "Two builds byte-identical: #{receipt['physical_pe_count']} PEs, #{receipt['pe_bytes']} bytes, #{inputs.length} source/artifact observations"
