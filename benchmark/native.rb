# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "benchmark"
require "libinjection"

SAMPLES = {
  benign_short: "ordinary search text",
  sqli_short: "1 OR 1=1--",
  xss_short: "<script>alert(1)</script>",
  benign_1kb: "a" * 1024,
  sqli_1kb: ("a" * 1000) + " 1 OR 1=1--",
  benign_8kb: "a" * (8 * 1024)
}.freeze

ITERATIONS = Integer(ENV.fetch("ITERATIONS", "100000"))

puts "Ruby #{RUBY_VERSION} (#{RUBY_PLATFORM})"
puts "libinjection #{LibInjection.lib_version}"
puts "iterations=#{ITERATIONS}"

Benchmark.bm(18) do |x|
  SAMPLES.each do |name, sample|
    x.report(name) do
      ITERATIONS.times { LibInjection.detect_raw(sample) }
    end
  end
end
