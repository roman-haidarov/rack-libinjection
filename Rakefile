# frozen_string_literal: true

require "bundler/gem_tasks"
require "rake/testtask"
require "rake/extensiontask"

Rake::ExtensionTask.new("libinjection_native") do |ext|
  ext.lib_dir = "lib/libinjection"
  ext.ext_dir = "ext/libinjection"
end

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/*_test.rb", "test/**/test_*.rb"]
end

namespace :security do
  desc "Run native security smoke checks with random/binary inputs"
  task smoke: :compile do
    ruby "script/fuzz_smoke.rb"
  end
end

namespace :vendor do
  desc "Download and vendor pinned libinjection source"
  task :sync do
    ruby "script/vendor_libs.rb --sync"
  end

  desc "Verify vendored libinjection source"
  task :verify do
    ruby "script/vendor_libs.rb --verify"
  end
end

desc "Download and vendor pinned libinjection source"
task vendor: "vendor:sync"

desc "Vendor, compile, security smoke, and test"
task full_build: [:vendor, :compile, "security:smoke", :test]

task default: [:compile, :test]
