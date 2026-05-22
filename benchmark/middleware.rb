# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "benchmark"
require "rack/mock"
require "rack/libinjection"

ITERATIONS = Integer(ENV.fetch("ITERATIONS", "10000"))

app = Rack::LibInjection.new(
  ->(_env) { [200, { "content-type" => "text/plain" }, ["ok"]] },
  mode: :report,
  scan: [:params],
  notifier: ->(*) {}
)
request = Rack::MockRequest.new(app)

puts "Ruby #{RUBY_VERSION} (#{RUBY_PLATFORM})"
puts "iterations=#{ITERATIONS}"

Benchmark.bm(20) do |x|
  x.report("benign params") do
    ITERATIONS.times { request.get("/search?q=ordinary&sort=desc") }
  end

  x.report("sqli params") do
    ITERATIONS.times { request.get("/search?q=1%20OR%201%3D1--") }
  end
end
