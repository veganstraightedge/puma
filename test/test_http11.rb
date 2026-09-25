# frozen_string_literal: true

# Copyright (c) 2011 Evan Phoenix
# Copyright (c) 2005 Zed A. Shaw

require_relative "helper"
require_relative "helpers/integration"
require "digest"

class Http11ParserTest < TestIntegration

  parallelize_me! unless ::Puma::IS_JRUBY && RUBY_DESCRIPTION.include?('x86_64-darwin')

  def test_parse_simple
    parser = Puma::HttpParser.new
    req = {}
    http = "GET /?a=1 HTTP/1.1\r\n\r\n"
    nread = parser.execute(req, http, 0)

    assert nread == http.length, "Failed to parse the full HTTP request"
    assert parser.finished?, "Parser didn't finish"
    assert !parser.error?, "Parser had error"
    assert nread == parser.nread, "Number read returned from execute does not match"

    assert_equal '/', req['REQUEST_PATH']
    assert_equal 'HTTP/1.1', req['SERVER_PROTOCOL']
    assert_equal '/?a=1', req['REQUEST_URI']
    assert_equal 'GET', req['REQUEST_METHOD']
    assert_nil req['FRAGMENT']
    assert_equal "a=1", req['QUERY_STRING']

    parser.reset
    assert parser.nread == 0, "Number read after reset should be 0"
  end

  def test_parse_escaping_in_query
    parser = Puma::HttpParser.new
    req = {}
    http = "GET /admin/users?search=%27%%27 HTTP/1.1\r\n\r\n"
    nread = parser.execute(req, http, 0)

    assert nread == http.length, "Failed to parse the full HTTP request"
    assert parser.finished?, "Parser didn't finish"
    assert !parser.error?, "Parser had error"
    assert nread == parser.nread, "Number read returned from execute does not match"

    assert_equal '/admin/users?search=%27%%27', req['REQUEST_URI']
    assert_equal "search=%27%%27", req['QUERY_STRING']

    parser.reset
    assert parser.nread == 0, "Number read after reset should be 0"
  end

  def test_parse_absolute_uri
    parser = Puma::HttpParser.new
    req = {}
    http = "GET http://192.168.1.96:3000/api/v1/matches/test?1=1 HTTP/1.1\r\n\r\n"
    nread = parser.execute(req, http, 0)

    assert nread == http.length, "Failed to parse the full HTTP request"
    assert parser.finished?, "Parser didn't finish"
    assert !parser.error?, "Parser had error"
    assert nread == parser.nread, "Number read returned from execute does not match"

    assert_equal "GET", req['REQUEST_METHOD']
    assert_equal 'http://192.168.1.96:3000/api/v1/matches/test?1=1', req['REQUEST_URI']
    assert_equal 'HTTP/1.1', req['SERVER_PROTOCOL']

    assert_nil req['REQUEST_PATH']
    assert_nil req['FRAGMENT']
    assert_nil req['QUERY_STRING']

    parser.reset
    assert parser.nread == 0, "Number read after reset should be 0"

  end

  def test_parse_dumbfuck_headers
    parser = Puma::HttpParser.new
    req = {}
    should_be_good = "GET / HTTP/1.1\r\naaaaaaaaaaaaa:++++++++++\r\n\r\n"
    nread = parser.execute(req, should_be_good, 0)
    assert_equal should_be_good.length, nread
    assert parser.finished?
    assert !parser.error?
  end

  def test_parse_error
    parser = Puma::HttpParser.new
    req = {}
    bad_http = "GET / SsUTF/1.1"

    error = false
    begin
      parser.execute(req, bad_http, 0)
    rescue
      error = true
    end

    assert error, "failed to throw exception"
    assert !parser.finished?, "Parser shouldn't be finished"
    assert parser.error?, "Parser SHOULD have error"
  end

  def test_fragment_in_uri
    parser = Puma::HttpParser.new
    req = {}
    get = "GET /forums/1/topics/2375?page=1#posts-17408 HTTP/1.1\r\n\r\n"

    parser.execute(req, get, 0)

    assert parser.finished?
    assert_equal '/forums/1/topics/2375?page=1', req['REQUEST_URI']
    assert_equal 'posts-17408', req['FRAGMENT']
  end

  def test_semicolon_in_path
    parser = Puma::HttpParser.new
    req = {}
    get = "GET /forums/1/path;stillpath/2375?page=1 HTTP/1.1\r\n\r\n"

    parser.execute(req, get, 0)

    assert parser.finished?
    assert_equal '/forums/1/path;stillpath/2375?page=1', req['REQUEST_URI']
    assert_equal '/forums/1/path;stillpath/2375', req['REQUEST_PATH']
  end

  # lame random garbage maker
  def rand_data(min, max, readable=true)
    count = min + ((rand(max)+1) *10).to_i
    res = count.to_s + "/"

    if readable
      res << Digest(:SHA1).hexdigest(rand(count * 100).to_s) * (count / 40)
    else
      data = Digest(:SHA1).digest(rand(count * 100).to_s) * (count / 20)
      # Guarantee there is an invalid byte at the end of the string
      data.setbyte(data.bytesize - 1, 0x1)
      res << data
    end

    res
  end

  def test_get_const_length
    skip_unless :jruby

    envs = %w[
      PUMA_REQUEST_URI_MAX_LENGTH
      PUMA_REQUEST_PATH_MAX_LENGTH
      PUMA_QUERY_STRING_MAX_LENGTH
    ]
    default_exp = [1024 * 12, 8192, 10 * 1024]
    tests = [{ envs: %w[60000 61000 62000], exp: [60000, 61000, 62000], error_indexes: [] },
             { envs: ['', 'abc', nil], exp: default_exp, error_indexes: [1] },
             { envs: %w[-4000 0 3000.45], exp: default_exp, error_indexes: [0, 1, 2] }]
    cli_config = <<~CONFIG
        app do |_|
          [200, {}, [JSONSerialization.generate({
                       MAX_REQUEST_URI_LENGTH:      org.jruby.puma.Http11::MAX_REQUEST_URI_LENGTH,
                       MAX_REQUEST_PATH_LENGTH:     org.jruby.puma.Http11::MAX_REQUEST_PATH_LENGTH,
                       MAX_QUERY_STRING_LENGTH:     org.jruby.puma.Http11::MAX_QUERY_STRING_LENGTH,
                       MAX_REQUEST_URI_LENGTH_ERR:  org.jruby.puma.Http11::MAX_REQUEST_URI_LENGTH_ERR,
                       MAX_REQUEST_PATH_LENGTH_ERR: org.jruby.puma.Http11::MAX_REQUEST_PATH_LENGTH_ERR,
                       MAX_QUERY_STRING_LENGTH_ERR: org.jruby.puma.Http11::MAX_QUERY_STRING_LENGTH_ERR })]]
        end
    CONFIG

    tests.each do |conf|
      cli_server 'test/rackup/hello.ru',
        env: {envs[0]  => conf[:envs][0], envs[1] => conf[:envs][1], envs[2] => conf[:envs][2]},
        merge_err: true,
        config: cli_config

      sleep 0.25
      result = JSON.parse read_body(connect)

      assert_equal conf[:exp][0], result['MAX_REQUEST_URI_LENGTH']
      assert_equal conf[:exp][1], result['MAX_REQUEST_PATH_LENGTH']
      assert_equal conf[:exp][2], result['MAX_QUERY_STRING_LENGTH']

      assert_includes result['MAX_REQUEST_URI_LENGTH_ERR'], "longer than the #{conf[:exp][0]} allowed length"
      assert_includes result['MAX_REQUEST_PATH_LENGTH_ERR'], "longer than the #{conf[:exp][1]} allowed length"
      assert_includes result['MAX_QUERY_STRING_LENGTH_ERR'], "longer than the #{conf[:exp][2]} allowed length"

      conf[:error_indexes].each do |index|
        assert_includes @server_log, "The value #{conf[:envs][index]} for #{envs[index]} is invalid. "\
          "Using default value #{default_exp[index]} instead"
      end

      stop_server
     end
  end

  def test_max_uri_path_length
    parser = Puma::HttpParser.new
    req = {}

    # Support URI path length to a max of 8192
    path = "/" + rand_data(7000, 100)
    http = "GET #{path} HTTP/1.1\r\n\r\n"
    parser.execute(req, http, 0)
    assert_equal path, req['REQUEST_PATH']
    parser.reset

    # Raise exception if URI path length > 8192
    path = "/" + rand_data(9000, 100)
    http = "GET #{path} HTTP/1.1\r\n\r\n"
    assert_raises Puma::HttpParserError do
      parser.execute(req, http, 0)
    end
    parser.reset
  end

  def test_horrible_queries
    parser = Puma::HttpParser.new

    # then that large header names are caught
    10.times do |c|
      get = "GET /#{rand_data(10,120)} HTTP/1.1\r\nX-#{rand_data(1024, 1024+(c*1024))}: Test\r\n\r\n"
      assert_raises Puma::HttpParserError do
        parser.execute({}, get, 0)
      end
      parser.reset
    end

    # then that large mangled field values are caught
    10.times do |c|
      get = "GET /#{rand_data(10,120)} HTTP/1.1\r\nX-Test: #{rand_data(1024, 1024+(c*1024), false)}\r\n\r\n"
      assert_raises Puma::HttpParserError do
        parser.execute({}, get, 0)
      end
      parser.reset
    end

    # then large headers are rejected too
    mult = TRUFFLE ? 10 : 80
    get = "GET /#{rand_data(10,120)} HTTP/1.1\r\n" \
      "#{"X-Test: test\r\n" * (mult * 1024)}"
    assert_raises Puma::HttpParserError do
      parser.execute({}, get, 0)
    end
    parser.reset

    # finally just that random garbage gets blocked all the time
    10.times do |c|
      get = "GET #{rand_data(1024, 1024+(c*1024), false)} #{rand_data(1024, 1024+(c*1024), false)}\r\n\r\n"
      assert_raises Puma::HttpParserError do
        parser.execute({}, get, 0)
      end
      parser.reset
    end
  end

  def test_trims_whitespace_from_headers
    parser = Puma::HttpParser.new
    req = {}
    http = "GET / HTTP/1.1\r\nX-Strip-Me: \t Strip This \t      \r\n\r\n"

    parser.execute(req, http, 0)

    assert_equal "Strip This", req["HTTP_X_STRIP_ME"]
  end

  def test_newline_smuggler
    parser = Puma::HttpParser.new
    req = {}
    http = "GET / HTTP/1.1\r\nHost: localhost:8080\r\nDummy: x\nDummy2: y\r\n\r\n"

    parser.execute(req, http, 0) rescue nil # We test the raise elsewhere.

    assert parser.error?, "Parser SHOULD have error"
  end

  def test_newline_smuggler_two
    parser = Puma::HttpParser.new
    req = {}
    http = "GET / HTTP/1.1\r\nHost: localhost:8080\r\nDummy: x\r\nDummy: y\nDummy2: z\r\n\r\n"

    parser.execute(req, http, 0) rescue nil

    assert parser.error?, "Parser SHOULD have error"
  end

  def test_htab_in_header_val
    parser = Puma::HttpParser.new
    req = {}
    http = "GET / HTTP/1.1\r\nHost: localhost:8080\r\nDummy: Valid\tValue\r\n\r\n"

    parser.execute(req, http, 0)

    assert_equal "Valid\tValue", req['HTTP_DUMMY']
  end

  def test_parse_in_chunks
    parser = Puma::HttpParser.new
    req = {}
    buffer = +""
    nread = 0

    ["GET /ab", "c?d=1 HTTP/1.1\r\nHo", "st: x\r\n\r\nbody"].each do |chunk|
      refute parser.finished?
      buffer << chunk
      nread = parser.execute(req, buffer, nread)
    end

    assert parser.finished?
    assert_equal buffer.bytesize - "body".bytesize, nread
    assert_equal '/abc', req['REQUEST_PATH']
    assert_equal 'd=1', req['QUERY_STRING']
    assert_equal '/abc?d=1', req['REQUEST_URI']
    assert_equal 'x', req['HTTP_HOST']
    assert_equal 'body', parser.body
  end

  def test_error_in_later_chunk
    parser = Puma::HttpParser.new
    req = {}
    buffer = +"GET / HT"
    nread = parser.execute(req, buffer, 0)
    refute parser.error?

    buffer << "TX"
    assert_raises(Puma::HttpParserError) { parser.execute(req, buffer, nread) }
    assert parser.error?
    refute parser.finished?
  end

  def test_execute_after_finished_is_an_error
    parser = Puma::HttpParser.new
    buffer = +"GET / HTTP/1.1\r\n\r\n"
    nread = parser.execute({}, buffer, 0)
    assert parser.finished?

    buffer << "GET / HTTP/1.1\r\n\r\n"
    assert_raises(Puma::HttpParserError) { parser.execute({}, buffer, nread) }
    assert parser.error?
  end

  def test_start_after_buffer_end
    parser = Puma::HttpParser.new
    http = "GET / HTTP/1.1\r\n\r\n"

    error = assert_raises(Puma::HttpParserError) { parser.execute({}, http, http.bytesize) }
    assert_equal "Requested start is after data buffer end.", error.message
  end

  def test_body
    parser = Puma::HttpParser.new
    http = "GET / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"
    nread = parser.execute({}, http, 0)

    assert_equal http.bytesize - 3, nread
    assert_equal "abc", parser.body

    parser.reset
    # the Java parser keeps the previous body after reset
    assert_nil parser.body unless Puma.http_parser_engine == "java"
    parser.execute({}, "GET / HTTP/1.1\r\n\r\n", 0)
    assert_equal "", parser.body
  end

  def test_duplicate_headers_are_joined
    parser = Puma::HttpParser.new
    req = {}
    parser.execute(req, "GET / HTTP/1.1\r\nX-A: 1\r\nx-a: 2\r\n\r\n", 0)

    assert_equal "1, 2", req['HTTP_X_A']
  end

  def test_empty_header_value
    parser = Puma::HttpParser.new
    req = {}
    parser.execute(req, "GET / HTTP/1.1\r\nX-Empty:\r\nX-Spaces:   \r\nX-Tab:\tv\r\n\r\n", 0)

    assert_equal "", req['HTTP_X_EMPTY']
    assert_equal "", req['HTTP_X_SPACES']
    assert_equal "v", req['HTTP_X_TAB']
  end

  def test_underscore_in_header_name_becomes_comma
    parser = Puma::HttpParser.new
    req = {}
    parser.execute(req, "GET / HTTP/1.1\r\nX_Forwarded_For: 1\r\nX-Forwarded-For: 2\r\n\r\n", 0)

    assert_equal "1", req['HTTP_X,FORWARDED,FOR']
    assert_equal "2", req['HTTP_X_FORWARDED_FOR']
  end

  def test_content_length_and_type_keys_have_no_prefix
    parser = Puma::HttpParser.new
    req = {}
    parser.execute(req, "GET / HTTP/1.1\r\ncontent-length: 3\r\ncontent-type: t\r\n\r\nabc", 0)

    assert_equal "3", req['CONTENT_LENGTH']
    assert_equal "t", req['CONTENT_TYPE']
    assert_nil req['HTTP_CONTENT_LENGTH']
  end

  def test_star_request_uri
    parser = Puma::HttpParser.new
    req = {}
    parser.execute(req, "OPTIONS * HTTP/1.1\r\n\r\n", 0)

    assert_equal "OPTIONS", req['REQUEST_METHOD']
    assert_equal "*", req['REQUEST_URI']
    assert_nil req['REQUEST_PATH']
  end

  def test_high_bytes_in_uri
    parser = Puma::HttpParser.new
    req = {}
    parser.execute(req, "GET /caf\xC3\xA9?x=\xFF HTTP/1.1\r\n\r\n".b, 0)

    assert_equal "/caf\xC3\xA9".b, req['REQUEST_PATH']
    assert_equal "x=\xFF".b, req['QUERY_STRING']
  end

  def test_env_values_are_binary_and_keys_utf8
    skip "the Java parser returns binary env keys" if Puma.http_parser_engine == "java"
    parser = Puma::HttpParser.new
    req = {}
    parser.execute(req, "GET /a?b=c HTTP/1.1\r\nHost: h\r\nX-Unusual: u\r\n\r\n", 0)

    req.each do |key, value|
      assert_equal Encoding::UTF_8, key.encoding, key
      assert_equal Encoding::BINARY, value.encoding, key
    end
  end

  def test_method_length_limit
    parser = Puma::HttpParser.new
    req = {}
    parser.execute(req, "#{'A' * 20} / HTTP/1.1\r\n\r\n", 0)
    assert_equal 'A' * 20, req['REQUEST_METHOD']

    parser.reset
    assert_raises(Puma::HttpParserError) { parser.execute({}, "#{'A' * 21} / HTTP/1.1\r\n\r\n", 0) }
  end

  def test_run_end_regexps_agree_with_byte_tables
    skip "pure Ruby parser only" unless Puma.http_parser_engine == "ruby"
    parser = Puma::HttpParser

    {
      parser::METHOD_BYTE => parser::METHOD_RUN_END,
      parser::SCHEME_BYTE => parser::SCHEME_RUN_END,
      parser::URI_BYTE => parser::URI_RUN_END,
      parser::PATH_BYTE => parser::PATH_RUN_END,
      parser::FIELD_NAME_BYTE => parser::FIELD_NAME_RUN_END,
      parser::FIELD_VALUE_BYTE => parser::FIELD_VALUE_RUN_END
    }.each do |table, run_end|
      256.times do |byte|
        assert_equal table[byte], !run_end.match?(byte.chr.b), "#{run_end.inspect} byte #{byte}"
      end
    end
  end

  # The one-match header line path must be exactly as strict as the byte tables,
  # since only lines it rejects reach the byte by byte path.
  def test_header_line_regexp_agrees_with_byte_tables
    skip "pure Ruby parser only" unless Puma.http_parser_engine == "ruby"
    parser = Puma::HttpParser

    256.times do |byte|
      in_name = "#{byte.chr}: v\r\n".b
      assert_equal parser::FIELD_NAME_BYTE[byte], parser::HEADER_LINE.match?(in_name), "name byte #{byte}"

      in_value = "X: a#{byte.chr}b\r\n".b
      assert_equal parser::FIELD_VALUE_BYTE[byte], parser::HEADER_LINE.match?(in_value), "value byte #{byte}"
    end

    assert parser::HEADER_LINE.match?("X:\r\n".b)
    assert parser::HEADER_LINE.match?("X:   \tv \r\n".b)
    refute parser::HEADER_LINE.match?("X : v\r\n".b)
    refute parser::HEADER_LINE.match?(": v\r\n".b)
    refute parser::HEADER_LINE.match?("X: v\n".b)
    refute parser::HEADER_LINE.match?("X: v\r\n".b, 1)
  end

  def test_rejects_lowercase_method_and_bare_word_uri
    ["get / HTTP/1.1\r\n\r\n", "GET abc HTTP/1.1\r\n\r\n", "GET  / HTTP/1.1\r\n\r\n", "GET / HTTP/1.\r\n\r\n"].each do |http|
      parser = Puma::HttpParser.new
      assert_raises(Puma::HttpParserError, http) { parser.execute({}, http, 0) }
      assert parser.error?, http
    end
  end
end
