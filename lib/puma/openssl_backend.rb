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
  end
end

require_relative "openssl_backend/context_builder"
