# frozen_string_literal: true

require "mkmf"
require "rbconfig"

USE_SYSTEM = arg_config("--use-system-libinjection") || ENV["LIBINJECTION_USE_SYSTEM"] == "1"

EXT_DIR            = __dir__
PRIMARY_VENDOR_DIR = File.join(EXT_DIR, "vendor", "libinjection")

REQUIRED_VENDOR_FILES = %w[
  src/libinjection.h
  src/libinjection_error.h
  src/libinjection_sqli.h
  src/libinjection_sqli_data.h
  src/libinjection_xss.h
  src/libinjection_html5.h
  src/libinjection_sqli.c
  src/libinjection_xss.c
  src/libinjection_html5.c
].freeze


def compiler_version
  cc = RbConfig::CONFIG.fetch("CC", "cc")
  `#{cc} --version 2>&1`
rescue StandardError
  ""
end

def gcc_without_clang?
  version = compiler_version.downcase
  version.include?("gcc") && !version.include?("clang")
end
def vendor_ready?(dir)
  File.file?(File.join(dir, ".vendored")) && REQUIRED_VENDOR_FILES.all? { |path| File.file?(File.join(dir, path)) }
end

def abort_missing_vendor!
  abort <<~MSG
    libinjection vendored sources are missing.

    Run:
      ruby script/vendor_libs.rb

    Security note: extconf.rb does not auto-download native sources during build.
  MSG
end

def find_vendor_dir
  candidates = [PRIMARY_VENDOR_DIR]

  dir = __dir__
  6.times do
    candidates << File.join(dir, "ext", "libinjection", "vendor", "libinjection")
    dir = File.dirname(dir)
  end

  candidates.map! { |path| File.expand_path(path) }
  candidates.uniq!

  abort_missing_vendor! unless vendor_ready?(PRIMARY_VENDOR_DIR)
  candidates.find { |path| vendor_ready?(path) }
end

def configure_system!
  puts "Building with SYSTEM libinjection"

  if find_executable("pkg-config")
    cflags = `pkg-config --cflags libinjection 2>/dev/null`.strip
    libs   = `pkg-config --libs   libinjection 2>/dev/null`.strip
    $CPPFLAGS << " #{cflags}" unless cflags.empty?
    $libs     << " #{libs}"   unless libs.empty?
  end

  abort "libinjection.h is required"        unless have_header("libinjection.h")
  abort "libinjection_sqli.h is required"   unless have_header("libinjection_sqli.h")
  abort "libinjection_xss.h is required"    unless have_header("libinjection_xss.h")
  abort "libinjection library is required"  unless have_library("injection", "libinjection_sqli")
  abort "libinjection_version() is required" unless have_func("libinjection_version")
end

def configure_vendored!(vendor_dir)
  abort "libinjection vendored sources are missing" unless vendor_dir

  versions = File.read(File.join(vendor_dir, ".vendored"))
  puts "Building with VENDORED libinjection from #{vendor_dir}"
  puts "  #{versions.tr("\n", ", ")}"

  src_dir = File.join(vendor_dir, "src")
  $CPPFLAGS << " -I#{src_dir}"
  $srcs  = %w[libinjection_ext.c libinjection_sqli.c libinjection_xss.c libinjection_html5.c]
  $VPATH = [EXT_DIR, src_dir]
end

$CFLAGS    << " -std=c99 -Wall -Wextra -O3"
$CFLAGS    << " -Wno-unused-function -Wno-unused-parameter"

if ENV["LIBINJECTION_SANITIZE"] == "1"
  $CFLAGS  << " -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer"
  $LDFLAGS << " -fsanitize=address,undefined"
end

$CFLAGS    << " -Wno-enum-int-mismatch" if gcc_without_clang?
$warnflags  = ""

unless $CFLAGS.include?("LI_NOGVL_THRESHOLD")
  $CFLAGS << " -DLI_NOGVL_THRESHOLD=1024"
end

USE_SYSTEM ? configure_system! : configure_vendored!(find_vendor_dir)

create_makefile("libinjection/libinjection_native")
