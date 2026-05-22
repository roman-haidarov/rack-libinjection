# frozen_string_literal: true

require_relative "test_helper"

class TestLibInjection < Minitest::Test
  def test_sqli_detection
    assert_equal true, LibInjection.sqli?("1 OR 1=1--")
  end

  def test_sqli_fingerprint
    fingerprint = LibInjection.sqli_fingerprint("1 OR 1=1--")
    assert_kind_of String, fingerprint
    refute_empty fingerprint
  end

  def test_benign_string
    assert_equal false, LibInjection.sqli?("ordinary search text")
    assert_nil LibInjection.sqli_fingerprint("ordinary search text")
  end

  def test_empty_string_is_safe
    assert_equal false, LibInjection.sqli?("")
    assert_equal false, LibInjection.xss?("")
    assert_nil LibInjection.detect_raw("")
  end

  def test_nil_is_rejected
    assert_raises TypeError do
      LibInjection.detect_raw(nil)
    end
  end

  def test_binary_invalid_utf8_is_scanned_as_bytes
    input = "\xFF\xFE1 OR 1=1--".b
    input.force_encoding(Encoding::UTF_8)

    assert_equal false, input.valid_encoding?
    assert_equal :sqli, LibInjection.detect_raw(input).fetch(0)
  end

  def test_null_bytes_do_not_crash
    input = "abc\0<script>alert(1)</script>".b

    assert_equal :xss, LibInjection.detect_raw(input).fetch(0)
  end

  def test_utf16_is_not_implicitly_decoded
    input = "1 OR 1=1--".encode(Encoding::UTF_16LE)

    assert_nil LibInjection.detect_raw(input)
  end

  def test_large_input_uses_nogvl_path_safely
    input = "1 OR 1=1--" + ("a" * 2_048)

    assert_equal :sqli, LibInjection.detect_raw(input).fetch(0)
  end

  def test_detect_raw_sqli
    match = LibInjection.detect_raw("1 OR 1=1--")

    assert_equal :sqli, match[0]
    assert_kind_of String, match[1]
  end

  def test_detect_raw_xss
    match = LibInjection.detect_raw("<script>alert(1)</script>")

    assert_equal :xss, match[0]
    assert_nil match[1]
  end

  def test_detect_raw_benign
    assert_nil LibInjection.detect_raw("ordinary search text")
  end

  def test_detect_result
    result = LibInjection.detect("1 OR 1=1--")
    assert result.detected?
    assert result.sqli?
  end

  def test_sqli_result
    result = LibInjection.sqli_result("1 OR 1=1--")

    assert_equal :sqli, result[:type]
    assert_equal true, result[:detected]
    assert_kind_of String, result[:fingerprint]
    assert_kind_of Hash, result[:stats]
  end

  def test_sqli_result_rejects_invalid_options
    assert_raises ArgumentError do
      LibInjection.sqli_result("1 OR 1=1--", context: :unknown)
    end

    assert_raises ArgumentError do
      LibInjection.sqli_result("1 OR 1=1--", quote: :unknown)
    end

    assert_raises ArgumentError do
      LibInjection.sqli_result("1 OR 1=1--", dialect: :unknown)
    end
  end

  def test_sqli_contexts
    contexts = LibInjection.sqli_contexts("1 OR 1=1--")

    refute_empty contexts
    assert contexts.any? { |ctx| ctx[:detected] }
    assert contexts.all? { |ctx| ctx.key?(:context) && ctx.key?(:flags) }
  end

  def test_sqli_context_flags
    assert_equal LibInjection::SQLI_CONTEXTS.fetch(:single_mysql),
                 LibInjection.sqli_flags(context: :single_mysql)
    assert_equal LibInjection::SQLI_QUOTES.fetch(:single) | LibInjection::SQLI_DIALECTS.fetch(:mysql),
                 LibInjection.sqli_flags(quote: :single, dialect: :mysql)
  end

  def test_sqli_fingerprint_for_context
    fp = LibInjection.sqli_fingerprint_for("1 OR 1=1--", context: :none_ansi)

    assert_kind_of String, fp
    refute_empty fp
  end

  def test_sqli_tokens
    tokens = LibInjection.sqli_tokens("1 OR 1=1--")

    refute_empty tokens
    assert_equal :number, tokens.first[:type]
    assert_equal "1", tokens.first[:value]
  end

  def test_sqli_tokens_rejects_invalid_options
    assert_raises ArgumentError do
      LibInjection.sqli_tokens("1 OR 1=1--", context: :unknown)
    end
  end

  def test_sqli_folded_tokens
    tokens = LibInjection.sqli_tokens("1 OR 1=1--", fold: true)

    refute_empty tokens
    assert tokens.size <= LibInjection.sqli_tokens("1 OR 1=1--").size
  end

  def test_xss_detection
    assert_equal true, LibInjection.xss?("<script>alert(1)</script>")
  end

  def test_xss_result
    result = LibInjection.xss_result("<script>alert(1)</script>")

    assert_equal :xss, result[:type]
    assert_equal true, result[:detected]
  end

  def test_xss_result_rejects_invalid_options
    assert_raises ArgumentError do
      LibInjection.xss_result("<script>alert(1)</script>", context: :unknown)
    end
  end

  def test_xss_contexts
    contexts = LibInjection.xss_contexts("<script>alert(1)</script>")

    refute_empty contexts
    assert contexts.any? { |ctx| ctx[:detected] }
  end

  def test_html5_tokens
    tokens = LibInjection.html5_tokens("<script>alert(1)</script>")

    refute_empty tokens
    assert_equal :tag_name_open, tokens.first[:type]
    assert_equal "script", tokens.first[:value]
  end

  def test_html5_tokens_rejects_invalid_options
    assert_raises ArgumentError do
      LibInjection.html5_tokens("<script>alert(1)</script>", context: :unknown)
    end
  end

  def test_html5_context_flags
    assert_equal LibInjection::HTML5_CONTEXTS.fetch(:value_double_quote),
                 LibInjection.xss_flags(context: :value_double_quote)
  end
  def test_detect_url_encoded_raw_decodes_twice
    match = LibInjection.detect_url_encoded_raw("q=1%2520OR%25201%253D1--", 2, true, 3)

    assert_equal :sqli, match.fetch(0)
  end

  def test_detect_url_encoded_raw_respects_depth
    assert_nil LibInjection.detect_url_encoded_raw("q=1%2520OR%25201%253D1--", 1, true, 3)
  end

  def test_detect_url_encoded_raw_can_scan_only_xss
    match = LibInjection.detect_url_encoded_raw("q=%3Cscript%3Ealert(1)%3C/script%3E", 2, true, 2)

    assert_equal :xss, match.fetch(0)
  end

  def test_detect_url_encoded_raw_accepts_malformed_percent_escapes
    assert_nil LibInjection.detect_url_encoded_raw("q=%ZZordinary", 2, true, 3)
  end

  def test_detect_url_encoded_raw_rejects_excessive_depth
    assert_raises ArgumentError do
      LibInjection.detect_url_encoded_raw("q=ordinary", 33, true, 3)
    end
  end

  def test_detect_url_encoded_raw_rejects_invalid_mask
    assert_raises ArgumentError do
      LibInjection.detect_url_encoded_raw("q=ordinary", 2, true, 0)
    end
  end

end
