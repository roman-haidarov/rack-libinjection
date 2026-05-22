#!/usr/bin/env ruby
# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "securerandom"
require "libinjection"

PAYLOADS = [
  "",
  "1 OR 1=1--",
  "<script>alert(1)</script>",
  "abc\0def".b,
  "\xFF\xFE1 OR 1=1--".b,
  ("a" * 2_048) + " 1 OR 1=1--",
  "1 OR 1=1--".encode(Encoding::UTF_16LE)
].freeze

PAYLOADS.each do |payload|
  LibInjection.detect(payload)
  LibInjection.sqli?(payload)
  LibInjection.xss?(payload)
end

1_000.times do |i|
  bytes = SecureRandom.random_bytes(rand(0..4096))
  bytes.force_encoding([Encoding::BINARY, Encoding::UTF_8].sample)

  LibInjection.detect_raw(bytes)
  LibInjection.sqli?(bytes)
  LibInjection.xss?(bytes)
rescue LibInjection::ParserError
  next
rescue StandardError => e
  warn "fuzz smoke failed at iteration #{i}: #{e.class}: #{e.message}"
  raise
end

puts "fuzz smoke: ok"
