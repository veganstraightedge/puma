# frozen_string_literal: true

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
    TAB = 9
    LF = 10
    CR = 13
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
    TSPECIAL_BYTES = "()<>@,;:\\\"/[]?={} \t".bytes
    # token = ascii -- (CTL | tspecials)
    FIELD_NAME_BYTE = Array.new(256) { |byte| byte < 128 && !CONTROL_BYTES.include?(byte) && !TSPECIAL_BYTES.include?(byte) }.freeze
    # (any -- CTL) | "\t"
    FIELD_VALUE_BYTE = Array.new(256) { |byte| byte == TAB || !CONTROL_BYTES.include?(byte) }.freeze

    METHOD_MAX_LENGTH = 20
    PROTOCOL_PREFIX = "HTTP/"
    HTTP_PREFIX = "HTTP_"

    # Env keys for the headers we expect to receive, so that parsing them
    # allocates no key strings. CONTENT_LENGTH and CONTENT_TYPE have no HTTP_
    # prefix, following the CGI convention.
    COMMON_FIELDS = {
      "ACCEPT" => "HTTP_ACCEPT",
      "ACCEPT_CHARSET" => "HTTP_ACCEPT_CHARSET",
      "ACCEPT_ENCODING" => "HTTP_ACCEPT_ENCODING",
      "ACCEPT_LANGUAGE" => "HTTP_ACCEPT_LANGUAGE",
      "ALLOW" => "HTTP_ALLOW",
      "AUTHORIZATION" => "HTTP_AUTHORIZATION",
      "CACHE_CONTROL" => "HTTP_CACHE_CONTROL",
      "CONNECTION" => "HTTP_CONNECTION",
      "CONTENT_ENCODING" => "HTTP_CONTENT_ENCODING",
      "CONTENT_LENGTH" => "CONTENT_LENGTH",
      "CONTENT_TYPE" => "CONTENT_TYPE",
      "COOKIE" => "HTTP_COOKIE",
      "DATE" => "HTTP_DATE",
      "EXPECT" => "HTTP_EXPECT",
      "FROM" => "HTTP_FROM",
      "HOST" => "HTTP_HOST",
      "IF_MATCH" => "HTTP_IF_MATCH",
      "IF_MODIFIED_SINCE" => "HTTP_IF_MODIFIED_SINCE",
      "IF_NONE_MATCH" => "HTTP_IF_NONE_MATCH",
      "IF_RANGE" => "HTTP_IF_RANGE",
      "IF_UNMODIFIED_SINCE" => "HTTP_IF_UNMODIFIED_SINCE",
      "KEEP_ALIVE" => "HTTP_KEEP_ALIVE",
      "MAX_FORWARDS" => "HTTP_MAX_FORWARDS",
      "PRAGMA" => "HTTP_PRAGMA",
      "PROXY_AUTHORIZATION" => "HTTP_PROXY_AUTHORIZATION",
      "RANGE" => "HTTP_RANGE",
      "REFERER" => "HTTP_REFERER",
      "TE" => "HTTP_TE",
      "TRAILER" => "HTTP_TRAILER",
      "TRANSFER_ENCODING" => "HTTP_TRANSFER_ENCODING",
      "UPGRADE" => "HTTP_UPGRADE",
      "USER_AGENT" => "HTTP_USER_AGENT",
      "VIA" => "HTTP_VIA",
      "WARNING" => "HTTP_WARNING",
      "X_FORWARDED_FOR" => "HTTP_X_FORWARDED_FOR",
      "X_REAL_IP" => "HTTP_X_REAL_IP"
    }.freeze

    REQUEST_METHOD = "REQUEST_METHOD"
    REQUEST_URI = "REQUEST_URI"
    FRAGMENT = "FRAGMENT"
    QUERY_STRING = "QUERY_STRING"
    SERVER_PROTOCOL = "SERVER_PROTOCOL"
    REQUEST_PATH = "REQUEST_PATH"

    INVALID_FORMAT_MESSAGE = "Invalid HTTP format, parsing fails. Are you trying to open an SSL connection to a non-SSL Puma?"

    # Maximum allowed lengths of the request elements, and their error messages.
    # The messages spell the limits exactly as the C extension does, where they
    # come from the macro text, e.g. "(1024 * 12)". Tests assert on them.
    MAX_FIELD_NAME_LENGTH = 256
    MAX_FIELD_NAME_LENGTH_ERR = "HTTP element FIELD_NAME is longer than the 256 allowed length (was %d)"
    MAX_FIELD_VALUE_LENGTH = 80 * 1024
    MAX_FIELD_VALUE_LENGTH_ERR = "HTTP element FIELD_VALUE is longer than the 80 * 1024 allowed length (was %d)"
    MAX_REQUEST_URI_LENGTH = 1024 * 12
    MAX_REQUEST_URI_LENGTH_ERR = "HTTP element REQUEST_URI is longer than the (1024 * 12) allowed length (was %d)"
    MAX_FRAGMENT_LENGTH = 1024
    MAX_FRAGMENT_LENGTH_ERR = "HTTP element FRAGMENT is longer than the 1024 allowed length (was %d)"
    MAX_REQUEST_PATH_LENGTH = 8192
    MAX_REQUEST_PATH_LENGTH_ERR = "HTTP element REQUEST_PATH is longer than the (8192) allowed length (was %d)"
    MAX_QUERY_STRING_LENGTH = 1024 * 10
    MAX_QUERY_STRING_LENGTH_ERR = "HTTP element QUERY_STRING is longer than the (1024 * 10) allowed length (was %d)"
    MAX_HEADER_LENGTH = 1024 * (80 + 32)
    MAX_HEADER_LENGTH_ERR = "HTTP element HEADER is longer than the (1024 * (80 + 32)) allowed length (was %d)"

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
      @field_start = 0
      @field_len = 0
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

      validate_max_length(@nread, MAX_HEADER_LENGTH, MAX_HEADER_LENGTH_ERR)
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
          elsif FIELD_NAME_BYTE[byte]
            @field_start = position
            state = :field_name
          else
            state = :error
            break
          end
        when :field_name
          if FIELD_NAME_BYTE[byte]
            # continue
          elsif byte == COLON
            @field_len = position - @field_start
            state = :field_value_start
          else
            state = :error
            break
          end
        when :field_value_start
          if byte == SPACE
            # leading spaces are not part of the value
          elsif FIELD_VALUE_BYTE[byte]
            @mark = position
            state = :field_value
          elsif byte == CR
            @mark = position
            http_field(position)
            state = :header_lf
          else
            state = :error
            break
          end
        when :field_value
          if FIELD_VALUE_BYTE[byte]
            # continue
          elsif byte == CR
            http_field(position)
            state = :header_lf
          else
            state = :error
            break
          end
        when :header_lf
          if byte == LF
            state = :header_line
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

    def validate_max_length(length, max_length, message)
      raise HttpParserError, format(message, length) if length > max_length
    end

    def http_field(position)
      value_length = position - @mark
      validate_max_length(@field_len, MAX_FIELD_NAME_LENGTH, MAX_FIELD_NAME_LENGTH_ERR)
      validate_max_length(value_length, MAX_FIELD_VALUE_LENGTH, MAX_FIELD_VALUE_LENGTH_ERR)

      # Upcase, "-" becomes "_", and "_" becomes "," so that a header with
      # underscores cannot impersonate one with dashes.
      name = @data.byteslice(@field_start, @field_len).upcase.tr("-_", "_,")
      key = COMMON_FIELDS[name] || -"#{HTTP_PREFIX}#{name}"

      value = @data.byteslice(@mark, value_length)
      # Only spaces and tabs can be present; the grammar rejects other control bytes.
      value.strip!

      existing = @env[key]
      if existing.nil?
        @env[key] = value
      else
        # duplicate headers are normalized to comma-separated values
        existing << ", " << value
      end
    end

    def request_method(position)
      @env[REQUEST_METHOD] = @data.byteslice(@mark, position - @mark)
    end

    def request_uri(position)
      length = position - @mark
      validate_max_length(length, MAX_REQUEST_URI_LENGTH, MAX_REQUEST_URI_LENGTH_ERR)
      @env[REQUEST_URI] = @data.byteslice(@mark, length)
    end

    def fragment(position)
      length = position - @mark
      validate_max_length(length, MAX_FRAGMENT_LENGTH, MAX_FRAGMENT_LENGTH_ERR)
      @env[FRAGMENT] = @data.byteslice(@mark, length)
    end

    def request_path(position)
      length = position - @mark
      validate_max_length(length, MAX_REQUEST_PATH_LENGTH, MAX_REQUEST_PATH_LENGTH_ERR)
      @env[REQUEST_PATH] = @data.byteslice(@mark, length)
    end

    def query_string(position)
      length = position - @query_start
      validate_max_length(length, MAX_QUERY_STRING_LENGTH, MAX_QUERY_STRING_LENGTH_ERR)
      @env[QUERY_STRING] = @data.byteslice(@query_start, length)
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
