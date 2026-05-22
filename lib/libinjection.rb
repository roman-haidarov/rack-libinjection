# frozen_string_literal: true

require_relative "libinjection/version"

module LibInjection
  class Error       < StandardError; end
  class ParserError < Error; end
end

begin
  require_relative "libinjection/libinjection_native"
rescue LoadError
  require "libinjection/libinjection_native"
end

module LibInjection
  Result = Data.define(:type, :detected, :fingerprint) do
    def detected? = !!detected
    def sqli?     = type == :sqli && detected?
    def xss?      = type == :xss  && detected?
  end

  module_function

  def detect(input)
    raw = detect_raw(input)
    return Result.new(type: nil, detected: false, fingerprint: nil) if raw.nil?

    Result.new(type: raw[0], detected: true, fingerprint: raw[1])
  end
end
