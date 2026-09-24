# frozen_string_literal: true

# Copyright (c) 2005 Zed A. Shaw
# You can redistribute it and/or modify it under the same terms as Ruby.
# License 3-clause BSD

module Puma
  class HttpParserError < StandardError; end

  # Pure Ruby port of the `puma_http11` C extension (`ext/puma_http11`).
  #
  # It is a streaming state machine that mirrors the Ragel grammar in
  # `ext/puma_http11/http11_parser_common.rl`, one state per grammar element.
  # `execute` may be called repeatedly with a growing buffer and the byte
  # offset returned by the previous call; the parser resumes where it left off.
  #
  # Behavior matches the C extension byte for byte, with one deliberate
  # exception: the C extension upcases header names inside the caller's
  # buffer as a side effect of parsing. This implementation never modifies
  # the buffer.
  class HttpParser
    CR = 13
    LF = 10
    SPACE = 32
    HASH = 35
    STAR = 42
    DOT = 46
    SLASH = 47
    COLON = 58
    QUESTION = 63

    # Byte lookup tables (index 0..255) for the character classes in the grammar.
    CONTROL_BYTES = (0..31).to_a << 127
    URI_EXCLUDED_BYTES = CONTROL_BYTES + " \"#<>".bytes

    # uchar | reserved
    URI_BYTE = Array.new(256) { |byte| !URI_EXCLUDED_BYTES.include?(byte) }.freeze
    # pchar | "/"
    PATH_BYTE = URI_BYTE.each_with_index.map { |allowed, byte| allowed && byte != QUESTION }.freeze
    # alpha | digit | "+" | "-" | "."
    SCHEME_BYTE = Array.new(256) { |byte| "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-.".bytes.include?(byte) }.freeze
    # upper | digit | safe
    METHOD_BYTE = Array.new(256) { |byte| "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$-_.".bytes.include?(byte) }.freeze
    DIGIT_BYTE = Array.new(256) { |byte| "0123456789".bytes.include?(byte) }.freeze

    METHOD_MAX_LENGTH = 20
    PROTOCOL_PREFIX = "HTTP/"

    REQUEST_METHOD = "REQUEST_METHOD"
    REQUEST_URI = "REQUEST_URI"
    FRAGMENT = "FRAGMENT"
    QUERY_STRING = "QUERY_STRING"
    SERVER_PROTOCOL = "SERVER_PROTOCOL"
    REQUEST_PATH = "REQUEST_PATH"

    INVALID_FORMAT_MESSAGE = "Invalid HTTP format, parsing fails. Are you trying to open an SSL connection to a non-SSL Puma?"

    def initialize
      reset
    end

    # Resets the parser to its initial state so that it can be reused
    # rather than making new ones.
    def reset
      @state = :method
      @nread = 0
      @mark = 0
      @query_start = 0
      @body_start = 0
      @body = nil
      @env = nil
      nil
    end

    # Finishes a parser early. You should call reset after finish.
    def finish
      finished?
    end

    def error?
      @state == :error
    end

    def finished?
      @state == :done
    end

    # The amount of data processed so far during this processing cycle.
    # It is 0 after initialize or reset and is incremented by each execute.
    attr_reader :nread

    # If the request included a body, returns it.
    attr_reader :body

    # Takes a Hash and a String of data, parses the String of data filling in
    # the Hash, returning an Integer to indicate how much of the data has been
    # read. Raises HttpParserError when the data is not valid HTTP.
    #
    # The third argument allows for parsing a partial request and then
    # continuing the parsing from that position. It needs all of the original
    # data as well, so you have to append to the data buffer as you read.
    def execute(env, data, start)
      if start >= data.bytesize
        raise HttpParserError, "Requested start is after data buffer end."
      end

      @env = env
      # Operate on bytes, like the C extension does.
      @data = data.b
      stopped_at = run(start, @data.bytesize)
      @nread += stopped_at - start

      raise HttpParserError, INVALID_FORMAT_MESSAGE if error?

      @nread
    end

    private

    # Runs the state machine over @data from position `from` up to `to`.
    # Returns the position it stopped at: `to` when more data is needed,
    # one past the final LF when done, or the offending byte on error.
    def run(from, to)
      state = @state
      position = from

      while position < to
        byte = @data.getbyte(position)

        case state
        when :method
          if METHOD_BYTE[byte] && position - @mark < METHOD_MAX_LENGTH
            # continue
          elsif byte == SPACE && position > @mark
            request_method(position)
            state = :uri_start
          else
            state = :error
            break
          end
        when :uri_start
          @mark = position
          if byte == SLASH then state = :path
          elsif byte == STAR then state = :uri_star
          elsif byte == COLON then state = :absolute_uri
          elsif SCHEME_BYTE[byte] then state = :scheme
          else
            state = :error
            break
          end
        when :uri_star
          if byte == SPACE
            request_uri(position)
            state = :protocol_start
          elsif byte == HASH
            request_uri(position)
            state = :fragment_start
          else
            state = :error
            break
          end
        when :scheme
          if SCHEME_BYTE[byte]
            # continue
          elsif byte == COLON
            state = :absolute_uri
          else
            state = :error
            break
          end
        when :absolute_uri
          if URI_BYTE[byte]
            # continue
          elsif byte == SPACE
            request_uri(position)
            state = :protocol_start
          elsif byte == HASH
            request_uri(position)
            state = :fragment_start
          else
            state = :error
            break
          end
        when :path
          if PATH_BYTE[byte]
            # continue
          elsif byte == QUESTION
            request_path(position)
            @query_start = position + 1
            state = :query
          elsif byte == SPACE
            request_path(position)
            request_uri(position)
            state = :protocol_start
          elsif byte == HASH
            request_path(position)
            request_uri(position)
            state = :fragment_start
          else
            state = :error
            break
          end
        when :query
          if URI_BYTE[byte]
            # continue
          elsif byte == SPACE
            query_string(position)
            request_uri(position)
            state = :protocol_start
          elsif byte == HASH
            query_string(position)
            request_uri(position)
            state = :fragment_start
          else
            state = :error
            break
          end
        when :fragment_start
          @mark = position
          if URI_BYTE[byte]
            state = :fragment
          elsif byte == SPACE
            fragment(position)
            state = :protocol_start
          else
            state = :error
            break
          end
        when :fragment
          if URI_BYTE[byte]
            # continue
          elsif byte == SPACE
            fragment(position)
            state = :protocol_start
          else
            state = :error
            break
          end
        when :protocol_start
          @mark = position
          if byte == PROTOCOL_PREFIX.getbyte(0)
            state = :protocol_prefix
          else
            state = :error
            break
          end
        when :protocol_prefix
          if byte == PROTOCOL_PREFIX.getbyte(position - @mark)
            state = :protocol_major if position - @mark == PROTOCOL_PREFIX.bytesize - 1
          else
            state = :error
            break
          end
        when :protocol_major
          if DIGIT_BYTE[byte]
            state = :protocol_major_digits
          else
            state = :error
            break
          end
        when :protocol_major_digits
          if DIGIT_BYTE[byte]
            # continue
          elsif byte == DOT
            state = :protocol_minor
          else
            state = :error
            break
          end
        when :protocol_minor
          if DIGIT_BYTE[byte]
            state = :protocol_minor_digits
          else
            state = :error
            break
          end
        when :protocol_minor_digits
          if DIGIT_BYTE[byte]
            # continue
          elsif byte == CR
            server_protocol(position)
            state = :request_line_lf
          else
            state = :error
            break
          end
        when :request_line_lf
          if byte == LF
            state = :header_line
          else
            state = :error
            break
          end
        when :header_line
          if byte == CR
            state = :final_lf
          else
            state = :error
            break
          end
        when :final_lf
          if byte == LF
            header_done(position)
            state = :done
            position += 1
            break
          else
            state = :error
            break
          end
        when :done
          state = :error
          break
        else
          break
        end

        position += 1
      end

      @state = state
      position
    end

    def request_method(position)
      @env[REQUEST_METHOD] = @data.byteslice(@mark, position - @mark)
    end

    def request_uri(position)
      @env[REQUEST_URI] = @data.byteslice(@mark, position - @mark)
    end

    def fragment(position)
      @env[FRAGMENT] = @data.byteslice(@mark, position - @mark)
    end

    def request_path(position)
      @env[REQUEST_PATH] = @data.byteslice(@mark, position - @mark)
    end

    def query_string(position)
      @env[QUERY_STRING] = @data.byteslice(@query_start, position - @query_start)
    end

    def server_protocol(position)
      @env[SERVER_PROTOCOL] = @data.byteslice(@mark, position - @mark)
    end

    def header_done(position)
      @body_start = position + 1
      @body = @data.byteslice(@body_start, @data.bytesize - @body_start)
    end
  end
end
