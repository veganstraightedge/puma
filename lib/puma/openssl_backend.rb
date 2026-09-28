# frozen_string_literal: true

require "openssl"

module Puma
  # An experimental SSL backend built on Ruby's openssl library, selected with
  # the +ssl_backend :openssl+ option. It takes the same +Puma::MiniSSL::Context+
  # as MiniSSL, so SSL settings work the same with either backend.
  module OpenSSLBackend
    MINIMUM_OPENSSL_GEM_VERSION = "3.0"

    if Gem::Version.new(OpenSSL::VERSION) < Gem::Version.new(MINIMUM_OPENSSL_GEM_VERSION)
      raise LoadError, "Puma's openssl SSL backend requires openssl gem #{MINIMUM_OPENSSL_GEM_VERSION} " \
        "or later, found #{OpenSSL::VERSION}. Add `gem \"openssl\"` to your Gemfile."
    end

    # Wraps a listening TCPServer, like +Puma::MiniSSL::Server+.
    class Server
      def initialize(socket, ctx)
        @socket = socket
        @ctx = ctx
        @ssl_context = ContextBuilder.new(ctx).ssl_context
      end

      # Accepts the TCP connection without handshaking. The handshake happens
      # on the first read, so the reactor waits on a slow client, not a thread.
      def accept
        @ctx.check
        Socket.new OpenSSL::SSL::SSLSocket.new(@socket.accept, @ssl_context)
      end

      def accept_nonblock
        @ctx.check
        Socket.new OpenSSL::SSL::SSLSocket.new(@socket.accept_nonblock, @ssl_context)
      end

      # @!attribute [r] to_io
      def to_io
        @socket
      end

      # @!attribute [r] addr
      def addr
        @socket.addr
      end

      def close
        @socket.close unless @socket.closed? # closed? call is for Windows
      end

      def closed?
        @socket.closed?
      end
    end

    # Wraps an +OpenSSL::SSL::SSLSocket+ with the interface Puma uses from
    # +Puma::MiniSSL::Socket+, raising +Puma::MiniSSL::SSLError+ for SSL errors.
    class Socket
      def initialize(ssl_socket)
        @ssl_socket = ssl_socket
        @ssl_socket.sync = true
        # So #sysclose closes the TCP socket too.
        @ssl_socket.sync_close = true
        @handshake_complete = false
        @failed_peercert = nil
      end

      # @!attribute [r] to_io
      def to_io
        @ssl_socket.io
      end

      def closed?
        @ssl_socket.io.closed?
      end

      # @!attribute [r] peeraddr
      def peeraddr
        @ssl_socket.io.peeraddr
      end

      def local_address
        @ssl_socket.io.local_address
      end

      # The client's certificate. When verification fails, it's the certificate
      # that failed, so it can be logged, as with MiniSSL.
      # @return [OpenSSL::X509::Certificate, nil]
      # @!attribute [r] peercert
      def peercert
        @failed_peercert || @ssl_socket.peer_cert
      end

      # Like +IO#read_nonblock+, but returns nil at EOF, as MiniSSL does. Can
      # return more than +size+, see #read_pending.
      def read_nonblock(size, buffer = nil, exception: true)
        return wait_readable(exception) unless handshake_complete?

        loop do
          data = translate_ssl_errors { @ssl_socket.read_nonblock(size, buffer, exception: false) }

          case data
          when String then return read_pending(data)
          when :wait_readable then return wait_readable(exception)
          when :wait_writable then @ssl_socket.io.wait_writable
          else return nil
          end
        end
      end

      def write(data)
        @ssl_socket.io.wait_readable until handshake_complete?
        translate_ssl_errors { @ssl_socket.write data }
      end

      alias_method :syswrite, :write
      alias_method :<<, :write

      # Raises +IO::EAGAINWaitWritable+ when the socket isn't writable, since
      # that's what Puma's write loop rescues.
      def write_nonblock(data, exception: true)
        @ssl_socket.io.wait_readable until handshake_complete?

        loop do
          written = translate_ssl_errors { @ssl_socket.write_nonblock(data, exception: false) }

          case written
          when :wait_writable
            raise IO::EAGAINWaitWritable if exception
            return :wait_writable
          when :wait_readable then @ssl_socket.io.wait_readable
          else return written
          end
        end
      end

      # Used by Puma's write loop after #write_nonblock raises +IO::EAGAINWaitWritable+.
      def wait_writable(timeout = nil)
        @ssl_socket.io.wait_writable timeout
      end

      def flush
        @ssl_socket.io.flush
      end

      # Sends close_notify when it can, then closes the TCP socket.
      def close
        read_unread_input unless @handshake_complete
        @ssl_socket.sysclose
      rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
        # Best effort, as with MiniSSL.
      ensure
        @ssl_socket.io.close unless @ssl_socket.io.closed?
      end

      private

      # OpenSSL decrypts a whole TLS record at a time, and keeps what wasn't
      # read. The socket isn't readable for that data, so the reactor would
      # never come back for it. Appends it to +data+, as MiniSSL does.
      def read_pending(data)
        while @ssl_socket.pending.positive?
          more = translate_ssl_errors { @ssl_socket.read_nonblock(@ssl_socket.pending, exception: false) }
          break unless more.is_a?(String)

          data << more
        end
        data
      end

      # Returns true once the handshake is complete, false while it waits on
      # the client.
      def handshake_complete?
        return true if @handshake_complete

        loop do
          result = translate_ssl_errors { @ssl_socket.accept_nonblock(exception: false) }

          case result
          when :wait_readable then return false
          when :wait_writable then @ssl_socket.io.wait_writable
          else return @handshake_complete = true
          end
        end
      end

      # After a failed handshake, OpenSSL may leave input unread, like a plain
      # HTTP request. Closing a socket with unread input sends a reset instead
      # of a FIN, so read it first.
      def read_unread_input
        loop do
          break unless @ssl_socket.io.read_nonblock(16_384, exception: false).is_a?(String)
        end
      end

      def wait_readable(exception)
        raise IO::EAGAINWaitReadable if exception
        :wait_readable
      end

      # The context's verify callback runs on this thread during the call, and
      # stores a certificate that fails verification in a thread local.
      def translate_ssl_errors
        Thread.current[ContextBuilder::FAILED_PEERCERT_KEY] = nil
        yield
      rescue OpenSSL::SSL::SSLError => e
        @failed_peercert ||= Thread.current[ContextBuilder::FAILED_PEERCERT_KEY]
        raise MiniSSL::SSLError, e.message
      end
    end
  end
end

require_relative "openssl_backend/context_builder"
