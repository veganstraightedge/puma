# frozen_string_literal: true

require_relative "helper"

if ::Puma::HAS_SSL && !::Puma::IS_JRUBY
  require "puma/minissl"
  require "puma/openssl_backend"
end

class TestOpenSSLBackendContextBuilder < PumaTest
  parallelize_me!

  CERT_PATH = File.expand_path "../examples/puma", __dir__

  def test_builds_a_frozen_ssl_context
    ssl_context = build_ssl_context

    assert_instance_of OpenSSL::SSL::SSLContext, ssl_context
    assert_predicate ssl_context, :frozen?
  end

  def test_cert_and_key_files
    ssl_context = build_ssl_context

    assert_equal certificate, peer_cert_from_handshake(ssl_context)
  end

  def test_cert_pem_and_key_pem
    ssl_context = build_ssl_context do |ctx|
      ctx.instance_variable_set :@cert, nil
      ctx.instance_variable_set :@key, nil
      ctx.cert_pem = File.read "#{CERT_PATH}/cert_puma.pem"
      ctx.key_pem = File.read "#{CERT_PATH}/puma_keypair.pem"
    end

    assert_equal certificate, peer_cert_from_handshake(ssl_context)
  end

  def test_encrypted_key_with_key_password_command
    skip_if :windows
    ssl_context = build_ssl_context do |ctx|
      ctx.key = "#{CERT_PATH}/encrypted_puma_keypair.pem"
      ctx.key_password_command = "#{CERT_PATH}/key_password_command.sh"
    end

    assert_equal certificate, peer_cert_from_handshake(ssl_context)
  end

  def test_key_password_command_not_run_for_unencrypted_key
    skip_if :windows
    ssl_context = build_ssl_context { |ctx| ctx.key_password_command = "false" }

    assert_equal certificate, peer_cert_from_handshake(ssl_context)
  end

  def test_failed_key_password_command_raises_its_error
    skip_if :windows
    error = assert_raises(RuntimeError) do
      build_ssl_context do |ctx|
        ctx.key = "#{CERT_PATH}/encrypted_puma_keypair.pem"
        ctx.key_password_command = "false"
      end
    end

    assert_includes error.message, "Key password failed"
  end

  def test_default_cipher_filter
    expected = OpenSSL::SSL::SSLContext.new.tap { |c| c.ciphers = "HIGH:!aNULL@STRENGTH" }.ciphers

    assert_equal expected, build_ssl_context.ciphers
  end

  def test_ssl_cipher_filter
    ssl_context = build_ssl_context { |ctx| ctx.ssl_cipher_filter = "ECDHE-RSA-AES128-GCM-SHA256" }

    assert_equal ["ECDHE-RSA-AES128-GCM-SHA256"], ssl_context.ciphers.map(&:first) - tls_1_3_cipher_names
  end

  def test_verify_mode_defaults_to_none
    assert_equal OpenSSL::SSL::VERIFY_NONE, build_ssl_context.verify_mode
  end

  def test_verify_mode
    ssl_context = build_ssl_context do |ctx|
      ctx.verify_mode = Puma::MiniSSL::VERIFY_PEER | Puma::MiniSSL::VERIFY_FAIL_IF_NO_PEER_CERT
    end

    assert_equal OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT, ssl_context.verify_mode
  end

  def test_ca
    ssl_context = build_ssl_context { |ctx| ctx.ca = "#{CERT_PATH}/client_certs/ca.crt" }

    assert_instance_of OpenSSL::X509::Store, ssl_context.cert_store
  end

  def test_session_cache_off_by_default
    assert_equal OpenSSL::SSL::SSLContext::SESSION_CACHE_OFF, build_ssl_context.session_cache_mode
  end

  def test_session_cache_reuse
    ssl_context = build_ssl_context { |ctx| ctx.reuse = "100,200" }

    assert_equal OpenSSL::SSL::SSLContext::SESSION_CACHE_SERVER, ssl_context.session_cache_mode
    assert_equal 100, ssl_context.session_cache_size
    assert_equal 200, ssl_context.timeout
  end

  def test_invalid_cert_raises_ssl_error
    assert_raises(Puma::MiniSSL::SSLError) { build_ssl_context { |ctx| ctx.cert = __FILE__ } }
  end

  def test_invalid_key_raises_ssl_error
    assert_raises(Puma::MiniSSL::SSLError) { build_ssl_context { |ctx| ctx.key = __FILE__ } }
  end

  def test_invalid_ca_raises_ssl_error
    assert_raises(Puma::MiniSSL::SSLError) { build_ssl_context { |ctx| ctx.ca = __FILE__ } }
  end

  private

  def build_ssl_context
    ctx = Puma::MiniSSL::Context.new
    ctx.cert = "#{CERT_PATH}/cert_puma.pem"
    ctx.key = "#{CERT_PATH}/puma_keypair.pem"
    yield ctx if block_given?
    Puma::OpenSSLBackend::ContextBuilder.new(ctx).ssl_context
  end

  def certificate
    OpenSSL::X509::Certificate.new File.read("#{CERT_PATH}/cert_puma.pem")
  end

  # Handshakes with a server using +ssl_context+, and returns the certificate
  # the client received.
  def peer_cert_from_handshake(ssl_context)
    tcp_server = TCPServer.new "127.0.0.1", 0
    server_thread = Thread.new do
      server = OpenSSL::SSL::SSLSocket.new tcp_server.accept, ssl_context
      server.accept
      server
    end

    client = OpenSSL::SSL::SSLSocket.new TCPSocket.new("127.0.0.1", tcp_server.addr[1])
    client.connect
    client.peer_cert
  ensure
    client&.close
    server_thread&.value&.close
    tcp_server&.close
  end

  def tls_1_3_cipher_names
    OpenSSL::SSL::SSLContext.new.ciphers.map(&:first).select { |name| name.start_with? "TLS_" }
  end
end if ::Puma::HAS_SSL && !::Puma::IS_JRUBY
