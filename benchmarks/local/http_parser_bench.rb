# frozen_string_literal: true

# Compares the parsing speed of the puma_http11 extension with the Ruby
# HttpParser (lib/puma/http_parser.rb). Run from the repo root:
#
#   bundle exec ruby benchmarks/local/http_parser_bench.rb
#
# It runs itself twice as a child process, once with PUMA_RUBY_HTTP_PARSER=true, so
# that both parsers are measured in the same Ruby, and prints a comparison
# table. The children get the JIT the parent runs with, e.g.
#
#   bundle exec ruby --yjit benchmarks/local/http_parser_bench.rb

require "json"
require "rbconfig"

ITERATIONS = Integer(ENV.fetch("ITERATIONS", 200_000))

REQUESTS = {
  "minimal GET" =>
    "GET / HTTP/1.1\r\n" \
    "Host: localhost\r\n" \
    "\r\n",
  "browser GET" =>
    "GET /articles/2026/09/hello-world?utm_source=news&ref=home HTTP/1.1\r\n" \
    "Host: www.example.com\r\n" \
    "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36\r\n" \
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n" \
    "Accept-Language: en-US,en;q=0.9\r\n" \
    "Accept-Encoding: gzip, deflate, br\r\n" \
    "Connection: keep-alive\r\n" \
    "Cookie: session=abc123def456; theme=dark; consent=1\r\n" \
    "Cache-Control: max-age=0\r\n" \
    "Upgrade-Insecure-Requests: 1\r\n" \
    "Sec-Fetch-Dest: document\r\n" \
    "Sec-Fetch-Mode: navigate\r\n" \
    "Sec-Fetch-Site: none\r\n" \
    "\r\n",
  "API POST" =>
    "POST /api/v1/orders HTTP/1.1\r\n" \
    "Host: api.example.com\r\n" \
    "Content-Type: application/json\r\n" \
    "Content-Length: 27\r\n" \
    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\r\n" \
    "Accept: application/json\r\n" \
    "X-Request-Id: 7f1c0e3a-1c2b-4d5e-8f90-123456789abc\r\n" \
    "User-Agent: curl/8.7.1\r\n" \
    "\r\n" \
    "{\"sku\":\"A1\",\"quantity\":2}"
}.freeze

# Parses each request ITERATIONS times with whichever HttpParser `require "puma"`
# loaded, and returns microseconds per request for each.
def measure
  require "puma"

  parser = Puma::HttpParser.new
  microseconds = REQUESTS.transform_values do |request|
    request = request.b
    # Each iteration parses a fresh copy, as a server would, because the C
    # extension upcases header names inside the buffer it parses.
    1_000.times do
      parser.execute({}, request.dup, 0)
      parser.reset
    end

    started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    ITERATIONS.times do
      parser.execute({}, request.dup, 0)
      parser.reset
    end
    seconds = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at
    seconds / ITERATIONS * 1_000_000
  end

  {
    "parser" => Puma.ruby_http_parser? ? "Ruby" : "puma_http11",
    "microseconds" => microseconds
  }
end

def jit_flags
  flags = []
  flags << "--yjit" if defined?(RubyVM::YJIT) && RubyVM::YJIT.enabled?
  flags << "--zjit" if defined?(RubyVM::ZJIT) && RubyVM::ZJIT.enabled?
  flags
end

def run_child(ruby_http_parser:)
  env = { "PUMA_RUBY_HTTP_PARSER" => ruby_http_parser ? "true" : nil }
  output = IO.popen([env, RbConfig.ruby, *jit_flags, "-Ilib", __FILE__, "--measure"], &:read)
  JSON.parse(output)
end

if ARGV.include?("--measure")
  puts JSON.generate(measure)
else
  native = run_child(ruby_http_parser: false)
  ruby = run_child(ruby_http_parser: true)
  jit = jit_flags.empty? ? "no JIT" : jit_flags.join(" ")

  puts "#{RUBY_DESCRIPTION}, #{jit}, #{ITERATIONS} iterations per request"
  puts
  puts "| request     | #{native['parser']} µs | #{ruby['parser']} µs | slowdown |"
  puts "|:------------|---------------:|--------:|---------:|"
  REQUESTS.each_key do |name|
    native_us = native["microseconds"][name]
    ruby_us = ruby["microseconds"][name]
    puts format("| %-11s | %14.2f | %7.2f | %7.1fx |", name, native_us, ruby_us, ruby_us / native_us)
  end
end
