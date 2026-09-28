# frozen_string_literal: true

# Compares the memory Puma uses for idle keep-alive connections with each SSL
# backend, MiniSSL and openssl, with plain HTTP as a baseline.
#
# For each server, it starts Puma, measures its resident memory (RSS), then
# a separate client process opens connections, sends one keep-alive request
# on each, and leaves them open. Idle keep-alive connections wait in Puma's
# reactor. It measures the memory again, then after the client closes the
# connections. Each is run several times, and the table shows the median.
#
#   bundle exec ruby benchmarks/local/ssl_memory.rb [connections] [runs]
#
# The defaults are 2,000 connections and 3 runs. It needs `fork`, so it
# doesn't run on Windows.

require 'etc'
require 'openssl'
require 'rbconfig'
require 'socket'

CONNECTIONS = Integer(ARGV[0] || 2_000)
RUNS        = Integer(ARGV[1] || 3)

# Time for Puma to settle after connections open or close.
SETTLE_SECONDS = 2

ROOT = File.expand_path '../..', __dir__
CERT = File.join ROOT, 'examples/puma/cert_puma.pem'
KEY  = File.join ROOT, 'examples/puma/puma_keypair.pem'
APP  = File.join ROOT, 'test/rackup/hello.ru'

REQUEST = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
RESPONSE_BODY = 'Hello World'

SERVERS = {
  'HTTP'    => { scheme: 'http',  ssl_backend: nil },
  'MiniSSL' => { scheme: 'https', ssl_backend: 'minissl' },
  'openssl' => { scheme: 'https', ssl_backend: 'openssl' },
}.freeze

def open_file_limit
  _soft, hard = Process.getrlimit :NOFILE
  wanted = CONNECTIONS + 256
  hard == Process::RLIM_INFINITY ? wanted : [wanted, hard].min
end

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
    '--threads', '4:4',
    '--bind', bind(scheme, port),
    '--quiet',
    APP
  ]
  pid = Process.spawn env, *command,
    chdir: ROOT,
    out: File::NULL,
    err: File::NULL,
    pgroup: true,
    rlimit_nofile: open_file_limit
  wait_for_port port
  pid
end

def stop_puma(pid)
  Process.kill 'TERM', pid
  Process.wait pid
end

# Resident memory in KiB. `ps` reports it the same way on macOS and Linux.
def rss_kib(pid)
  Integer(`ps -o rss= -p #{pid}`.strip)
end

def connect(scheme, port)
  socket = TCPSocket.new '127.0.0.1', port
  return socket if scheme == 'http'

  context = OpenSSL::SSL::SSLContext.new
  context.verify_mode = OpenSSL::SSL::VERIFY_NONE
  ssl_socket = OpenSSL::SSL::SSLSocket.new socket, context
  ssl_socket.sync_close = true
  ssl_socket.connect
  ssl_socket
end

def request(socket)
  socket.write REQUEST
  response = +''
  response << socket.readpartial(4_096) until response.end_with?(RESPONSE_BODY)
end

# Forks a client that opens +count+ keep-alive connections, and holds them
# open until the returned block is called.
def hold_connections(scheme, port, count)
  ready_reader, ready_writer = IO.pipe
  close_reader, close_writer = IO.pipe

  pid = fork do
    ready_reader.close
    close_writer.close
    Process.setrlimit :NOFILE, open_file_limit
    sockets = Array.new(count) { connect(scheme, port).tap { |socket| request socket } }
    ready_writer.puts 'ready'
    close_reader.gets
    sockets.each(&:close)
  end

  ready_writer.close
  close_reader.close
  raise 'client failed to open connections' unless ready_reader.gets

  lambda do
    close_writer.puts 'close'
    Process.wait pid
  end
end

def median(values)
  sorted = values.sort
  middle = sorted.size / 2
  sorted.size.odd? ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2.0
end

# @return [Hash] memory in KiB before, with, and after the connections
def measure_once(scheme:, ssl_backend:)
  port = free_port
  pid = start_puma port: port, scheme: scheme, ssl_backend: ssl_backend

  begin
    # Warm up, so allocations on first use aren't counted as per connection.
    close_connections = hold_connections scheme, port, 100
    close_connections.call
    sleep SETTLE_SECONDS
    before = rss_kib pid

    close_connections = hold_connections scheme, port, CONNECTIONS
    sleep SETTLE_SECONDS
    open = rss_kib pid

    close_connections.call
    sleep SETTLE_SECONDS
    after = rss_kib pid
  ensure
    stop_puma pid
  end

  { before: before, open: open, after: after }
end

def measure(server)
  results = Array.new(RUNS) { measure_once(**server) }
  before = median(results.map { |result| result[:before] })
  open = median(results.map { |result| result[:open] })
  after = median(results.map { |result| result[:after] })

  {
    before: before,
    open: open,
    after: after,
    per_connection: (open - before) / CONNECTIONS.to_f,
  }
end

def environment
  [
    "* #{RUBY_DESCRIPTION}",
    "* openssl gem #{OpenSSL::VERSION}, #{OpenSSL::OPENSSL_LIBRARY_VERSION}",
    "* #{RbConfig::CONFIG['host_os']}, #{Etc.nprocessors} CPUs",
    "* #{CONNECTIONS} idle keep-alive connections, median of #{RUNS} runs",
    "* Puma threads 4:4, single mode, `test/rackup/hello.ru`",
  ]
end

rows = SERVERS.map do |name, server|
  result = measure server
  $stderr.puts "#{name} done"
  [name, result]
end

puts environment, ''
puts '| Server | RSS before, MiB | RSS with connections open, MiB | KiB per connection | RSS after closing, MiB |'
puts '|:--|--:|--:|--:|--:|'
rows.each do |name, result|
  puts format('| %s | %.1f | %.1f | %.1f | %.1f |',
    name,
    result[:before] / 1_024.0,
    result[:open] / 1_024.0,
    result[:per_connection],
    result[:after] / 1_024.0)
end
