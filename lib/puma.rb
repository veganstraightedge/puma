# frozen_string_literal: true

# Standard libraries
require 'socket'
require 'tempfile'
require 'uri'
require 'stringio'

require 'thread'

require_relative 'puma/detect'

module Puma
  # The HTTP parser implementation, one of the following (as a string):
  # * c:    the puma_http11 C extension, the default on MRI
  # * java: the puma_http11 Java extension, the default on JRuby
  # * ruby: the puma/http_parser written in Ruby
  def self.http_parser_engine
    HTTP_PARSER_ENGINE
  end

  # The Ruby parser is opt-in with `PUMA_RUBY_HTTP_PARSER=true`.
  # It has no SSL support, since `MiniSSL::Engine` is only provided by the c-extension.
  def self.ruby_http_parser?(env = ENV)
    env['PUMA_RUBY_HTTP_PARSER'] == 'true'
  end
end

if Puma.ruby_http_parser?
  require_relative 'puma/http_parser'
  Puma::HTTP_PARSER_ENGINE = 'ruby'
else
  begin
    # use require, see https://github.com/puma/puma/pull/2381
    require 'puma/puma_http11'
  rescue LoadError => e
    raise LoadError, "#{e.message}\nPuma's puma_http11 extension is not available. " \
      "Reinstall the gem with a compiler, or set PUMA_RUBY_HTTP_PARSER=true to use the Ruby HTTP parser."
  end
  Puma::HTTP_PARSER_ENGINE = Puma.jruby? ? 'java' : 'c'
end

require_relative 'puma/json_serialization'

module Puma
  # when Puma is loaded via `Puma::CLI`, all files are loaded via
  # `require_relative`.  The below are for non-standard loading
  autoload :Const,     "#{__dir__}/puma/const"
  autoload :Server,    "#{__dir__}/puma/server"
  autoload :Launcher,  "#{__dir__}/puma/launcher"
  autoload :LogWriter, "#{__dir__}/puma/log_writer"

  # at present, MiniSSL::Engine is only defined in extension code (puma_http11),
  # not in minissl.rb
  HAS_SSL = const_defined?(:MiniSSL, false) && MiniSSL.const_defined?(:Engine, false)

  HAS_UNIX_SOCKET = Object.const_defined?(:UNIXSocket) && !IS_WINDOWS

  if HAS_SSL
    require_relative 'puma/minissl'
  else
    module MiniSSL
      # this class is defined so that it exists when Puma is compiled
      # without ssl support, as Server and Reactor use it in rescue statements.
      class SSLError < StandardError ; end
    end
  end

  def self.ssl?
    HAS_SSL
  end

  def self.abstract_unix_socket?
    @abstract_unix ||=
      if HAS_UNIX_SOCKET
        begin
          ::UNIXServer.new("\0puma.temp.unix").close
          true
        rescue ArgumentError  # darwin
          false
        end
      else
        false
      end
  end

  # @!attribute [rw] stats_object=
  def self.stats_object=(val)
    @get_stats = val
  end

  # @!attribute [rw] stats_object
  def self.stats
    Puma::JSONSerialization.generate @get_stats.stats
  end

  # @!attribute [r] stats_hash
  # @version 5.0.0
  def self.stats_hash
    @get_stats.stats
  end

  def self.set_thread_name(name)
    Thread.current.name = "puma #{name}"
  end

  # Shows deprecated warning for renamed methods.
  # @example
  #   Puma.deprecate_method_change :on_booted, __callee__, __method__
  #
  def self.deprecate_method_change(method_old, method_caller, method_new)
    if method_old == method_caller
      warn "Use '#{method_new}', '#{method_caller}' is deprecated and will be removed in Puma v9"
    end
  end
end
