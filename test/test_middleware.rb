# frozen_string_literal: true

require_relative "test_helper"

class TestRackLibInjection < Minitest::Test
  def app(**options)
    Rack::LibInjection.new(
      ->(env) { [200, { "content-type" => "text/plain" }, [env[Rack::LibInjection::ATTACK_ENV_KEY].inspect]] },
      **options
    )
  end

  def test_report_mode_continues_request
    res = Rack::MockRequest.new(app).get("/search?q=1%20OR%201%3D1--")
    assert_equal 200, res.status
    assert_includes res.body, ":sqli"
  end

  def test_block_mode_returns_403
    res = Rack::MockRequest.new(app(mode: :block)).get("/search?q=1%20OR%201%3D1--")
    assert_equal 403, res.status
  end

  def test_off_mode_does_not_scan_or_set_env_key
    res = Rack::MockRequest.new(app(mode: :off)).get("/search?q=1%20OR%201%3D1--")

    assert_equal 200, res.status
    assert_equal "nil", res.body
  end

  def test_empty_attack_list_is_mutable_for_downstream_rack_apps
    middleware = Rack::LibInjection.new(
      lambda { |env|
        attacks = env.fetch(Rack::LibInjection::ATTACK_ENV_KEY)
        attacks << :downstream_marker
        [200, { "content-type" => "text/plain" }, [attacks.inspect]]
      }
    )

    res = Rack::MockRequest.new(middleware).get("/clean?q=ordinary")

    assert_equal 200, res.status
    assert_includes res.body, ":downstream_marker"
  end

  def test_notifier_receives_payload
    events = []
    notifier = ->(event, payload) { events << [event, payload] }
    Rack::MockRequest.new(app(notifier: notifier)).get("/search?q=1%20OR%201%3D1--")

    assert_equal "rack.libinjection.attack", events.fetch(0).fetch(0)
    assert_equal :sqli, events.fetch(0).fetch(1).fetch(:type)
  end

  def test_xss_payload_is_reported
    res = Rack::MockRequest.new(app).get("/search?q=%3Cscript%3Ealert(1)%3C/script%3E")

    assert_equal 200, res.status
    assert_includes res.body, ":xss"
  end

  def test_ignore_params_skips_key_and_value
    events = []
    notifier = ->(event, payload) { events << [event, payload] }

    res = Rack::MockRequest.new(app(ignore_params: %w[q], notifier: notifier)).get("/search?q=1%20OR%201%3D1--")

    assert_equal 200, res.status
    refute_includes res.body, ":sqli"
    assert_empty events.select { |event, _| event == "rack.libinjection.attack" }
  end

  def test_nested_params_are_scanned
    res = Rack::MockRequest.new(app).get("/search?filter[items][]=1%20OR%201%3D1--")

    assert_equal 200, res.status
    assert_includes res.body, ":sqli"
    assert_includes res.body, "filter.items[0]"
  end

  def test_uploaded_filename_is_scanned
    middleware = app
    upload = Struct.new(:original_filename).new("1 OR 1=1--.jpg")
    attacks = []

    middleware.send(
      :walk_into,
      attacks,
      upload,
      location: :params,
      path: "avatar",
      depth: 0,
      context: { method: "POST", path: "/upload", ip: "127.0.0.1" }
    )

    assert_equal :sqli, attacks.fetch(0).type
    assert_equal "avatar.filename", attacks.fetch(0).key
  end

  def test_password_is_scanned_by_default
    res = Rack::MockRequest.new(app).get("/login?password=1%20OR%201%3D1--")

    assert_equal 200, res.status
    assert_includes res.body, ":sqli"
    assert_includes res.body, "password"
  end

  def test_max_value_bytes_skips_and_notifies
    events = []
    notifier = ->(event, payload) { events << [event, payload] }

    Rack::MockRequest.new(app(max_value_bytes: 3, notifier: notifier)).get("/search?q=abcd")

    skipped = events.find { |event, _| event == "rack.libinjection.skipped" }
    assert skipped
    assert_equal :max_value_bytes, skipped.fetch(1).fetch(:reason)
    assert_equal 4, skipped.fetch(1).fetch(:bytes)
  end

  def test_max_value_bytes_blocks_in_block_mode_by_default
    res = Rack::MockRequest.new(app(mode: :block, max_value_bytes: 3)).get("/search?q=abcd")

    assert_equal 403, res.status
  end

  def test_skipped_inputs_can_allow_oversized_values_in_block_mode
    res = Rack::MockRequest.new(app(mode: :block, max_value_bytes: 3, skipped_inputs: :allow)).get("/search?q=abcd")

    assert_equal 200, res.status
  end

  def test_max_depth_skips_and_notifies
    events = []
    notifier = ->(event, payload) { events << [event, payload] }

    Rack::MockRequest.new(app(max_depth: 0, notifier: notifier)).get("/search?a[b]=1")

    skipped = events.find { |event, _| event == "rack.libinjection.skipped" }
    assert skipped
    assert_equal :max_depth, skipped.fetch(1).fetch(:reason)
  end

  def test_max_depth_blocks_in_block_mode_by_default
    res = Rack::MockRequest.new(app(mode: :block, max_depth: 0)).get("/search?a[b]=1")

    assert_equal 403, res.status
  end

  def test_notify_skipped_can_be_disabled
    events = []
    notifier = ->(event, payload) { events << [event, payload] }

    Rack::MockRequest.new(app(max_value_bytes: 3, notify_skipped: false, notifier: notifier)).get("/search?q=abcd")

    assert_empty events
  end

  def test_path_scan_is_opt_in
    res = Rack::MockRequest.new(app(scan: %i[path])).get("/items/1%20OR%201=1--")

    assert_equal 200, res.status
    assert_includes res.body, ":sqli"
  end

  def test_path_scan_decodes_twice_by_default
    res = Rack::MockRequest.new(app(scan: %i[path])).get("/items/1%2520OR%25201%253D1--")

    assert_equal 200, res.status
    assert_includes res.body, ":sqli"
  end

  def test_path_segment_keys_start_at_zero_for_first_non_empty_segment
    middleware = app(scan: %i[path])
    attacks = []

    middleware.send(
      :scan_path_segments_into,
      attacks,
      "/1%20OR%201=1--/items",
      { method: "GET", path: "/1 OR 1=1--/items", ip: "127.0.0.1" }
    )

    assert_equal "path[0]", attacks.fetch(0).key
  end

  def test_path_decode_depth_has_hard_cap
    assert_raises ArgumentError do
      app(scan: %i[path], path_decode_depth: Rack::LibInjection::MAX_PATH_DECODE_DEPTH + 1)
    end
  end

  def test_path_decode_depth_can_disable_double_decode
    middleware = app(scan: %i[path], path_decode_depth: 1)
    attacks = []

    middleware.send(
      :scan_path_into,
      attacks,
      "/items/1%2520OR%25201%253D1--",
      { method: "GET", path: "/items", ip: "127.0.0.1" }
    )

    assert_empty attacks
  end

  def test_headers_scan_is_opt_in
    res = Rack::MockRequest.new(app(scan: %i[headers])).get("/", "HTTP_USER_AGENT" => "1 OR 1=1--")

    assert_equal 200, res.status
    assert_includes res.body, ":headers"
  end

  def test_standard_headers_are_ignored_by_default
    res = Rack::MockRequest.new(app(scan: %i[headers])).get("/", "HTTP_ACCEPT" => "1 OR 1=1--")

    assert_equal 200, res.status
    refute_includes res.body, ":headers"
  end

  def test_ignored_headers_can_be_overridden
    res = Rack::MockRequest.new(app(scan: %i[headers], ignore_headers: [])).get("/", "HTTP_ACCEPT" => "1 OR 1=1--")

    assert_equal 200, res.status
    assert_includes res.body, ":headers"
  end

  def test_cookies_scan_is_opt_in
    res = Rack::MockRequest.new(app(scan: %i[cookies])).get("/", "HTTP_COOKIE" => "q=1%20OR%201=1--")

    assert_equal 200, res.status
    assert_includes res.body, ":cookies"
  end

  def test_cookie_names_are_not_scanned_by_default
    middleware = app(scan: %i[cookies])
    req = Struct.new(:cookies).new({ "1 OR 1=1--" => "ordinary" })
    attacks = []

    middleware.send(:scan_cookies_into, attacks, req, { method: "GET", path: "/", ip: "127.0.0.1" })

    assert_empty attacks
  end

  def test_cookie_name_scanning_can_be_enabled
    middleware = app(scan: %i[cookies], scan_cookie_names: true)
    req = Struct.new(:cookies).new({ "1 OR 1=1--" => "ordinary" })
    attacks = []

    middleware.send(:scan_cookies_into, attacks, req, { method: "GET", path: "/", ip: "127.0.0.1" })

    assert_equal :sqli, attacks.fetch(0).type
    assert attacks.fetch(0).detected_in_key_name?
  end


  def test_query_scan_can_use_minimal_env_without_rack_request
    middleware = app(scan: %i[query])
    env = {
      "REQUEST_METHOD" => "GET",
      "PATH_INFO" => "/search",
      "QUERY_STRING" => "q=1%20OR%201%3D1--",
      "REMOTE_ADDR" => "127.0.0.1"
    }

    status, = middleware.call(env)

    assert_equal 200, status
    assert_equal :sqli, env.fetch(Rack::LibInjection::ATTACK_ENV_KEY).fetch(0).type
  end

  def test_query_scan_notifier_metadata_can_come_from_env
    events = []
    middleware = app(scan: %i[query], notifier: ->(event, payload) { events << [event, payload] })
    env = {
      "REQUEST_METHOD" => "GET",
      "PATH_INFO" => "/search",
      "QUERY_STRING" => "q=1%20OR%201%3D1--",
      "REMOTE_ADDR" => "127.0.0.1"
    }

    middleware.call(env)

    payload = events.fetch(0).fetch(1)
    assert_equal "GET", payload.fetch(:method)
    assert_equal "/search", payload.fetch(:path)
    assert_equal "127.0.0.1", payload.fetch(:ip)
  end

  def test_query_scan_is_fast_raw_surface
    res = Rack::MockRequest.new(app(scan: %i[query])).get("/search?q=1%20OR%201%3D1--")

    assert_equal 200, res.status
    assert_includes res.body, ":query"
    assert_includes res.body, ":sqli"
  end

  def test_query_scan_decodes_twice
    res = Rack::MockRequest.new(app(scan: %i[query])).get("/search?q=1%2520OR%25201%253D1--")

    assert_equal 200, res.status
    assert_includes res.body, ":query"
    assert_includes res.body, ":sqli"
  end


  def test_query_scan_decodes_plus_as_space_in_native_hot_path
    res = Rack::MockRequest.new(app(scan: %i[query])).get("/search?q=1+OR+1%3D1--")

    assert_equal 200, res.status
    assert_includes res.body, ":query"
    assert_includes res.body, ":sqli"
  end

  def test_query_decode_depth_zero_scans_only_raw_query
    res = Rack::MockRequest.new(app(scan: %i[query], path_decode_depth: 0)).get("/search?q=1%20OR%201%3D1--")

    assert_equal 200, res.status
    refute_includes res.body, ":sqli"
  end

  def test_threats_can_scan_only_sqli
    res = Rack::MockRequest.new(app(threats: %i[sqli])).get("/search?q=%3Cscript%3Ealert(1)%3C/script%3E")

    assert_equal 200, res.status
    refute_includes res.body, ":xss"
  end

  def test_threats_can_scan_only_xss
    res = Rack::MockRequest.new(app(threats: %i[xss])).get("/search?q=%3Cscript%3Ealert(1)%3C/script%3E")

    assert_equal 200, res.status
    assert_includes res.body, ":xss"
  end

  def test_parser_errors_block_in_block_mode_by_default
    middleware = app(mode: :block)
    middleware.define_singleton_method(:scan_params_into) do |_attacks, _req, _context|
      raise ::LibInjection::ParserError, "parser failure"
    end

    res = Rack::MockRequest.new(middleware).get("/search?q=ordinary")

    assert_equal 403, res.status
  end

  def test_parser_errors_can_raise
    middleware = app(parser_errors: :raise)
    middleware.define_singleton_method(:scan_params_into) do |_attacks, _req, _context|
      raise ::LibInjection::ParserError, "parser failure"
    end

    assert_raises ::LibInjection::ParserError do
      Rack::MockRequest.new(middleware).get("/search?q=ordinary")
    end
  end

  def test_parameter_parser_errors_block_in_block_mode
    error_class = Rack::LibInjection::PARAMETER_ERRORS.first || skip("Rack parameter error class unavailable")
    req = Object.new
    req.define_singleton_method(:params) { raise error_class, "bad params" }
    middleware = app(mode: :block)
    blocked = Rack::LibInjection.const_get(:ParserBlocked)

    assert_raises blocked do
      middleware.send(:scan_params_into, [], req, { method: "GET", path: "/", ip: "127.0.0.1" })
    end
  end

  def test_parameter_parser_errors_are_notified
    error_class = Rack::LibInjection::PARAMETER_ERRORS.first || RuntimeError
    req = Object.new
    req.define_singleton_method(:params) { raise error_class, "bad params" }
    events = []
    middleware = app(notifier: ->(event, payload) { events << [event, payload] })

    middleware.send(:scan_params_into, [], req, { method: "GET", path: "/", ip: "127.0.0.1" })

    event = events.find { |name, _| name == "rack.libinjection.error" }
    assert event
    assert_equal error_class.name, event.fetch(1).fetch(:error)
  end

  def test_notifier_errors_are_ignored_by_default
    res = Rack::MockRequest.new(app(notifier: ->(*) { raise "boom" })).get("/search?q=1%20OR%201%3D1--")

    assert_equal 200, res.status
  end

  def test_notifier_errors_can_raise
    assert_raises RuntimeError do
      Rack::MockRequest.new(app(notifier: ->(*) { raise "boom" }, notifier_errors: :raise)).get("/search?q=1%20OR%201%3D1--")
    end
  end

  def test_logger_wins_over_active_support_detection
    logger = Object.new
    messages = []
    logger.define_singleton_method(:warn) { |msg| messages << msg }

    Rack::MockRequest.new(app(logger: logger)).get("/search?q=1%20OR%201%3D1--")

    refute_empty messages
  end
end
