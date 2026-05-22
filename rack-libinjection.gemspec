# frozen_string_literal: true

require_relative "lib/libinjection/version"

Gem::Specification.new do |spec|
  spec.name          = "rack-libinjection"
  spec.version       = LibInjection::VERSION
  spec.authors       = ["Roman Haydarov"]
  spec.email         = ["romanhajdarov@gmail.com"]

  spec.summary       = "Tokenizer/fingerprint-based attack signal layer for Rack/Rails"
  spec.description   = "Native Ruby binding and Rack middleware for libinjection. " \
                        "Report-only by default: detects SQLi/XSS-like payloads, " \
                        "emits structured attack signals, and can be combined with Rack::Attack. " \
                        "Ships with a pinned vendoring workflow for libinjection v4.0.0."
  spec.homepage      = "https://github.com/roman-haidarov/rack-libinjection"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 3.3.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "#{spec.homepage}/tree/main"
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["security_policy_uri"] = "#{spec.homepage}/blob/main/SECURITY.md"

  vendor_files = Dir[
    "ext/libinjection/vendor/libinjection/.vendored",
    "ext/libinjection/vendor/libinjection/{COPYING,README.md,MIGRATION.md}",
    "ext/libinjection/vendor/libinjection/src/*.{c,h}"
  ]

  spec.files = (Dir[
    "lib/**/*.rb",
    "ext/libinjection/*.{c,rb}",
    "script/vendor_libs.rb",
    "script/fuzz_smoke.rb",
    "samples/**/*.rb",
    "samples/README.md",
    "samples/results/.gitkeep",
    "test/**/*.rb",
    ".github/workflows/ci.yml",
    "README.md",
    "GET_STARTED.md",
    "CHANGELOG.md",
    "SECURITY.md",
    "LICENSE.txt",
    "LICENSE-libinjection.txt"
  ] + vendor_files).select { |path| File.file?(path) && !File.symlink?(path) }.uniq

  spec.require_paths = ["lib"]
  spec.extensions = ["ext/libinjection/extconf.rb"]

  spec.add_dependency "rack", ">= 2.2", "< 4"

  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rake-compiler", "~> 1.2"
  spec.add_development_dependency "minitest", "~> 5.0"
end
