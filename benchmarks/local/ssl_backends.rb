# frozen_string_literal: true

# Compares Puma's SSL backends, MiniSSL and openssl, with plain HTTP as a
# baseline. It uses ApacheBench, `ab`, which ships with macOS, and with the
# apache2-utils package on Debian and Ubuntu.
# See https://httpd.apache.org/docs/current/programs/ab.html
#
# For each server, it runs `ab` with keep-alive, and with a new connection,
# so a new TLS handshake, for every request. Each is run several times, and the
# table shows the median.
#
#   bundle exec ruby benchmarks/local/ssl_backends.rb [requests] [concurrency] [runs]
#
# The defaults are 20,000 requests, a concurrency of 4, and 3 runs.

require 'etc'
require 'open3'
require 'openssl'
require 'rbconfig'
require 'socket'

REQUESTS    = Integer(ARGV[0] || 20_000)
CONCURRENCY = Integer(ARGV[1] || 4)
RUNS        = Integer(ARGV[2] || 3)

ROOT = File.expand_path '../..', __dir__
CERT = File.join ROOT, 'examples/puma/cert_puma.pem'
KEY  = File.join ROOT, 'examples/puma/puma_keypair.pem'
APP  = File.join ROOT, 'test/rackup/hello.ru'

SERVERS = {
  'HTTP'    => { scheme: 'http',  ssl_backend: nil },
  'MiniSSL' => { scheme: 'https', ssl_backend: 'minissl' },
  'openssl' => { scheme: 'https', ssl_backend: 'openssl' },
}.freeze

def free_port
  server = TCPServer.new '127.0.0.1', 0
  server.addr[1]
ensure
  server&.close
end

def bind(scheme, port)
  if scheme == 'https'
    "ssl://127.0.0.1:#{port}?cert=#{CERT}&key=#{KEY}&verify_mode=none"
  else
    "tcp://127.0.0.1:#{port}"
  end
end

def wait_for_port(port)
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 30
  begin
    TCPSocket.new('127.0.0.1', port).close
  rescue SystemCallError
    raise "Puma didn't start on port #{port}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

    sleep 0.1
    retry
  end
end

def start_puma(scheme:, ssl_backend:, port:)
  env = { 'PUMA_SSL_BACKEND' => ssl_backend }
  command = [
    RbConfig.ruby, 'bin/puma',
    '--threads', "#{CONCURRENCY}:#{CONCURRENCY}",
    '--bind', bind(scheme, port),
    '--quiet',
    APP
  ]
  pid = Process.spawn env, *command, chdir: ROOT, out: File::NULL, err: File::NULL, pgroup: true
  wait_for_port port
  pid
end

def stop_puma(pid)
  Process.kill 'TERM', pid
  Process.wait pid
end

# @return [Hash] requests per second, and mean milliseconds per request
def ab(url, keep_alive:, requests: REQUESTS)
  args = ['ab', '-q', '-n', requests.to_s, '-c', CONCURRENCY.to_s]
  args << '-k' if keep_alive
  args << url

  output, status = Open3.capture2e(*args)
  raise "ab failed:\n#{output}" unless status.success?

  failed = output[/^Failed requests:\s+(\d+)/, 1].to_i
  raise "ab had #{failed} failed requests:\n#{output}" unless failed.zero?

  {
    requests_per_second: Float(output[/^Requests per second:\s+([\d.]+)/, 1]),
    milliseconds_per_request: Float(output[/^Time per request:\s+([\d.]+) \[ms\] \(mean\)$/, 1]),
  }
end

def median(values)
  sorted = values.sort
  middle = sorted.size / 2
  sorted.size.odd? ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2.0
end

def measure(url, keep_alive:)
  ab url, keep_alive: keep_alive, requests: [REQUESTS / 10, 100].max # warm up
  results = Array.new(RUNS) { ab url, keep_alive: keep_alive }

  {
    requests_per_second: median(results.map { |result| result[:requests_per_second] }),
    milliseconds_per_request: median(results.map { |result| result[:milliseconds_per_request] }),
  }
end

def environment
  ab_version = Open3.capture2e('ab', '-V').first[/Version ([^\s,]+)/, 1]
  [
    "* #{RUBY_DESCRIPTION}",
    "* openssl gem #{OpenSSL::VERSION}, #{OpenSSL::OPENSSL_LIBRARY_VERSION}",
    "* #{RbConfig::CONFIG['host_os']}, #{Etc.nprocessors} CPUs",
    "* ApacheBench #{ab_version}, #{REQUESTS} requests, concurrency #{CONCURRENCY}, median of #{RUNS} runs",
    "* Puma threads #{CONCURRENCY}:#{CONCURRENCY}, single mode, `test/rackup/hello.ru`",
  ]
end

rows = SERVERS.map do |name, server|
  port = free_port
  pid = start_puma port: port, **server
  url = "#{server[:scheme]}://127.0.0.1:#{port}/"

  begin
    keep_alive = measure url, keep_alive: true
    new_connection = measure url, keep_alive: false
  ensure
    stop_puma pid
  end

  $stderr.puts "#{name} done"
  [name, keep_alive, new_connection]
end

puts environment, ''
puts '| Server | Keep-alive req/s | Keep-alive ms/req | New connection req/s | New connection ms/req |'
puts '|:--|--:|--:|--:|--:|'
rows.each do |name, keep_alive, new_connection|
  puts format('| %s | %.0f | %.3f | %.0f | %.3f |',
    name,
    keep_alive[:requests_per_second],
    keep_alive[:milliseconds_per_request],
    new_connection[:requests_per_second],
    new_connection[:milliseconds_per_request])
end
