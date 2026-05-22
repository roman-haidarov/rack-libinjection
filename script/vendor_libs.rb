#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "net/http"
require "uri"
require "optparse"
require "rubygems/package"
require "tmpdir"
require "zlib"

VENDOR_ROOT = File.expand_path("../ext/libinjection/vendor", __dir__)
LIB_DIR = File.join(VENDOR_ROOT, "libinjection")
MANIFEST_PATH = File.join(LIB_DIR, ".vendored")
NORMALIZED_MTIME = Time.utc(2000, 1, 1).freeze
MANIFEST_HEADER = "# rack-libinjection vendor manifest. Do not edit by hand. Regenerate with: ruby script/vendor_libs.rb"

PIN = {
  name: "libinjection",
  version: "4.0.0",
  url: "https://codeload.github.com/libinjection/libinjection/tar.gz/v%<version>s?dummy=/",
  strip_prefix: "libinjection-%<version>s",
  sha256: "a69d27e3d98608df89203c4e1c00c034fe0f8c723017e4088ab53ce3ff5a9129",
  size: 2_237_310,
  keep: %w[
    COPYING
    README.md
    MIGRATION.md
    src/libinjection.h
    src/libinjection_error.h
    src/libinjection_html5.h
    src/libinjection_sqli.h
    src/libinjection_sqli_data.h
    src/libinjection_xss.h
    src/libinjection_sqli.c
    src/libinjection_xss.c
    src/libinjection_html5.c
  ]
}.freeze

options = { mode: :sync }
OptionParser.new do |opts|
  opts.banner = "Usage: script/vendor_libs.rb [--sync | --verify]"
  opts.on("--sync", "Download and vendor pinned libinjection source") { options[:mode] = :sync }
  opts.on("--verify", "Verify vendored source tree without network") { options[:mode] = :verify }
end.parse!

def normalize_tree!(directory)
  Dir.glob(File.join(directory, "**", "*"), File::FNM_DOTMATCH).each do |path|
    base = File.basename(path)
    next if base == "." || base == ".." || File.symlink?(path)

    if File.file?(path)
      File.chmod(0o644, path)
      File.utime(NORMALIZED_MTIME, NORMALIZED_MTIME, path)
    elsif File.directory?(path)
      File.chmod(0o755, path)
    end
  end
end

def tree_sha256_for(directory)
  entries = Dir.glob(File.join(directory, "**", "*"), File::FNM_DOTMATCH)
               .reject { |path| File.directory?(path) || File.symlink?(path) || %w[. .. .vendored].include?(File.basename(path)) }
               .sort

  digest = Digest::SHA256.new
  entries.each do |path|
    relative = path.sub(/\A#{Regexp.escape(directory)}\/?/, "")
    digest << relative << "\0"
    digest << File.binread(path)
    digest << "\0"
  end
  digest.hexdigest
end

def manifest_body(tree_sha256)
  [
    "libinjection_version=#{PIN[:version]}",
    "libinjection_url=#{format(PIN[:url], version: PIN[:version])}",
    "libinjection_archive_sha256=#{PIN[:sha256]}",
    "libinjection_tree_sha256=#{tree_sha256}"
  ]
end

def write_manifest!(tree_sha256)
  content = ([MANIFEST_HEADER] + manifest_body(tree_sha256)).join("\n") + "\n"
  File.write(MANIFEST_PATH, content)
  File.chmod(0o644, MANIFEST_PATH)
  File.utime(NORMALIZED_MTIME, NORMALIZED_MTIME, MANIFEST_PATH)
end

def parse_manifest
  return {} unless File.file?(MANIFEST_PATH)

  File.readlines(MANIFEST_PATH, chomp: true).each_with_object({}) do |line, kv|
    next if line.empty? || line.start_with?("#")

    key, value = line.split("=", 2)
    kv[key] = value if key && value
  end
end

def verify_archive!(path)
  size = File.size(path)
  abort "Archive size mismatch: expected #{PIN[:size]}, got #{size}" unless size == PIN[:size]

  actual = Digest::SHA256.file(path).hexdigest
  abort "SHA256 mismatch: expected #{PIN[:sha256]}, got #{actual}" unless actual == PIN[:sha256]
end

def http_download_to_file!(url, path, redirect_limit: 3)
  abort "too many redirects while downloading #{url}" if redirect_limit.negative?

  uri = URI(url)
  Net::HTTP.start(
    uri.host,
    uri.port,
    use_ssl: uri.scheme == "https",
    open_timeout: 10,
    read_timeout: 30
  ) do |http|
    request = Net::HTTP::Get.new(uri)
    http.request(request) do |response|
      case response
      when Net::HTTPSuccess
        File.open(path, "wb") { |file| response.read_body { |chunk| file.write(chunk) } }
      when Net::HTTPRedirection
        location = response["location"]
        abort "redirect without Location while downloading #{url}" unless location

        return http_download_to_file!(URI.join(uri, location).to_s, path, redirect_limit: redirect_limit - 1)
      else
        abort "download failed: HTTP #{response.code} #{response.message}"
      end
    end
  end
end

def download_archive!(path)
  url = format(PIN[:url], version: PIN[:version])
  puts "Downloading #{url}"

  attempts = 0
  begin
    attempts += 1
    http_download_to_file!(url, path)
  rescue SystemCallError, IOError, Timeout::Error, Net::OpenTimeout, Net::ReadTimeout => e
    retry if attempts < 3

    abort "download failed after #{attempts} attempts: #{e.class}: #{e.message}"
  end

  verify_archive!(path)
end

def extract_archive!(archive)
  strip_prefix = format(PIN[:strip_prefix], version: PIN[:version])
  prefix_re = /\A#{Regexp.escape(strip_prefix)}\//

  FileUtils.rm_rf(LIB_DIR)
  FileUtils.mkdir_p(LIB_DIR)

  Gem::Package::TarReader.new(Zlib::GzipReader.open(archive)) do |tar|
    tar.each do |entry|
      relative = entry.full_name.sub(prefix_re, "")
      next if relative.empty? || relative == entry.full_name
      next unless PIN[:keep].include?(relative)
      next unless entry.file?

      target = File.join(LIB_DIR, relative)
      FileUtils.mkdir_p(File.dirname(target))
      File.binwrite(target, entry.read)
    end
  end

  missing = PIN[:keep].reject { |relative| File.file?(File.join(LIB_DIR, relative)) }
  abort "Missing expected vendored files:\n  #{missing.join("\n  ")}" unless missing.empty?

  normalize_tree!(LIB_DIR)
  tree_sha256_for(LIB_DIR)
end

def verify_vendor!
  failures = []
  manifest = parse_manifest

  expected_files = PIN[:keep] + [".vendored"]
  missing = expected_files.reject { |relative| File.file?(File.join(LIB_DIR, relative)) }
  failures << "missing files:\n  #{missing.join("\n  ")}" unless missing.empty?

  if manifest["libinjection_archive_sha256"] != PIN[:sha256]
    failures << "manifest archive sha256 does not match PIN"
  end

  if File.directory?(LIB_DIR)
    actual_tree = tree_sha256_for(LIB_DIR)
    manifest_tree = manifest["libinjection_tree_sha256"]
    failures << "tree_sha256 mismatch: manifest=#{manifest_tree.inspect} actual=#{actual_tree}" if manifest_tree && manifest_tree != actual_tree
  end

  if failures.empty?
    puts "vendor verify: ok"
    exit 0
  end

  failures.each { |failure| warn failure }
  exit 1
end

case options[:mode]
when :verify
  verify_vendor!
when :sync
  FileUtils.mkdir_p(VENDOR_ROOT)
  Dir.mktmpdir("rack-libinjection-vendor-") do |tmpdir|
    archive = File.join(tmpdir, "libinjection-#{PIN[:version]}.tar.gz")
    download_archive!(archive)
    tree = extract_archive!(archive)
    write_manifest!(tree)
    puts "vendor sync: ok"
    puts "  libinjection: version=#{PIN[:version]} archive_sha256=#{PIN[:sha256]} tree_sha256=#{tree}"
  end
else
  abort "unknown mode: #{options[:mode].inspect}"
end
