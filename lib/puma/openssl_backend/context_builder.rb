# frozen_string_literal: true

module Puma
  module OpenSSLBackend
    # Builds an +OpenSSL::SSL::SSLContext+ from a +Puma::MiniSSL::Context+, with
    # the same defaults as MiniSSL.
    class ContextBuilder
      DEFAULT_CIPHER_FILTER = "HIGH:!aNULL@STRENGTH"

      # The thread local where the verify callback stores a certificate that
      # fails verification, for +Puma::OpenSSLBackend::Socket#peercert+.
      FAILED_PEERCERT_KEY = :puma_openssl_backend_failed_peercert

      VERIFY_CALLBACK = lambda do |ok, store_context|
        Thread.current[FAILED_PEERCERT_KEY] = store_context.current_cert unless ok
        ok
      end

      def initialize(ctx)
        @ctx = ctx
      end

      # @return [OpenSSL::SSL::SSLContext] frozen, so it's shared safely across threads
      # @raise [Puma::MiniSSL::SSLError] if a certificate, key, or setting is invalid
      def ssl_context
        ssl_context = OpenSSL::SSL::SSLContext.new
        add_certificate ssl_context
        ssl_context.cert_store = cert_store if @ctx.ca || @ctx.verification_flags
        ssl_context.verify_mode = @ctx.verify_mode || OpenSSL::SSL::VERIFY_NONE
        ssl_context.verify_callback = VERIFY_CALLBACK if @ctx.verify_mode
        ssl_context.min_version = min_version
        ssl_context.ciphers = @ctx.ssl_cipher_filter || DEFAULT_CIPHER_FILTER
        ssl_context.ciphersuites = @ctx.ssl_ciphersuites if @ctx.ssl_ciphersuites
        ssl_context.options |= OpenSSL::SSL::OP_CIPHER_SERVER_PREFERENCE | OpenSSL::SSL::OP_NO_COMPRESSION
        set_session_cache ssl_context
        ssl_context.session_id_context = Random.bytes(32)

        # SSLContext#freeze is an alias of #setup, which returns true, not self.
        ssl_context.freeze
        ssl_context
      rescue OpenSSL::OpenSSLError, ArgumentError => e
        raise MiniSSL::SSLError, e.message
      end

      private

      def add_certificate(ssl_context)
        certificate, *chain = certificates

        # With no extra certificates, pass no chain, so OpenSSL builds it from
        # the CA store as MiniSSL does.
        if chain.empty?
          ssl_context.add_certificate certificate, private_key
        else
          ssl_context.add_certificate certificate, private_key, chain
        end
      end

      def certificates
        pem = @ctx.cert_pem || File.read(@ctx.cert)
        OpenSSL::X509::Certificate.load pem
      end

      def private_key
        pem = @ctx.key_pem || File.read(@ctx.key)
        return OpenSSL::PKey.read(pem) unless @ctx.key_password_command

        # OpenSSL only calls the block for an encrypted key. It discards an
        # error raised in the block, so keep it to raise instead.
        password_error = nil
        OpenSSL::PKey.read(pem) do
          @ctx.key_password
        rescue => e
          password_error = e
          nil
        end
      rescue OpenSSL::PKey::PKeyError
        raise password_error if password_error

        raise
      end

      def cert_store
        store = OpenSSL::X509::Store.new
        store.add_file @ctx.ca if @ctx.ca
        store.flags = @ctx.verification_flags if @ctx.verification_flags
        store
      end

      def min_version
        if @ctx.no_tlsv1_1
          OpenSSL::SSL::TLS1_2_VERSION
        elsif @ctx.no_tlsv1
          OpenSSL::SSL::TLS1_1_VERSION
        else
          OpenSSL::SSL::TLS1_VERSION
        end
      end

      def set_session_cache(ssl_context)
        unless @ctx.reuse
          ssl_context.session_cache_mode = OpenSSL::SSL::SSLContext::SESSION_CACHE_OFF
          return
        end

        ssl_context.session_cache_mode = OpenSSL::SSL::SSLContext::SESSION_CACHE_SERVER
        ssl_context.session_cache_size = @ctx.reuse_cache_size if @ctx.reuse_cache_size
        ssl_context.timeout = @ctx.reuse_timeout if @ctx.reuse_timeout
      end
    end
  end
end
