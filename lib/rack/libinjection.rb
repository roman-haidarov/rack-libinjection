# frozen_string_literal: true

require "rack/request"
require "libinjection"

module Rack
  class LibInjection
    DEFAULT_SCAN            = %i[params].freeze
    DEFAULT_THREATS         = %i[sqli xss].freeze
    DEFAULT_IGNORE_PARAMS   = %w[authenticity_token].freeze
    DEFAULT_IGNORE_HEADERS  = %w[
      accept
      accept-encoding
      accept-language
      cache-control
      connection
      content-length
      content-type
      host
      pragma
      sec-ch-ua
      sec-ch-ua-mobile
      sec-ch-ua-platform
      sec-fetch-dest
      sec-fetch-mode
      sec-fetch-site
      upgrade-insecure-requests
    ].freeze
    DEFAULT_MAX_VALUE_BYTES   = 8 * 1024
    DEFAULT_MAX_DEPTH         = 8
    DEFAULT_PATH_DECODE_DEPTH = 2

    ATTACK_ENV_KEY = "rack.libinjection.attacks"
    EVENT_NAME     = "rack.libinjection.attack"
    ERROR_EVENT    = "rack.libinjection.error"
    SKIPPED_EVENT  = "rack.libinjection.skipped"

    VALID_MODES = %i[report block off].freeze
    VALID_SCAN  = %i[query params path headers cookies].freeze
    VALID_THREATS = %i[sqli xss].freeze
    VALID_PARSER_ERRORS = %i[auto report block raise].freeze
    VALID_NOTIFIER_ERRORS = %i[ignore raise].freeze
    VALID_SKIPPED_INPUTS = %i[auto report block allow].freeze
    MAX_PATH_DECODE_DEPTH = 32

    PARAMETER_ERRORS = [
      defined?(::Rack::QueryParser::ParameterTypeError) && ::Rack::QueryParser::ParameterTypeError,
      defined?(::Rack::QueryParser::InvalidParameterError) && ::Rack::QueryParser::InvalidParameterError,
      defined?(::Rack::QueryParser::ParamsTooDeepError) && ::Rack::QueryParser::ParamsTooDeepError,
      defined?(::Rack::Utils::ParameterTypeError) && ::Rack::Utils::ParameterTypeError,
      defined?(::Rack::Utils::InvalidParameterError) && ::Rack::Utils::InvalidParameterError,
      defined?(::Rack::Utils::ParamsTooDeepError) && ::Rack::Utils::ParamsTooDeepError
    ].select { |value| value.is_a?(Class) }.uniq.freeze

    FORBIDDEN_HEADERS = { "content-type" => "text/plain; charset=utf-8" }.freeze
    FORBIDDEN_BODY    = ["Forbidden\n"].freeze

    NOOP_NOTIFIER = ->(_event, _payload) {}
    ParserBlocked = Class.new(StandardError)
    private_constant :ParserBlocked

    Attack = Data.define(:type, :location, :key, :key_name, :fingerprint, :bytes) do
      def sqli? = type == :sqli
      def xss?  = type == :xss
      def detected_in_key_name? = !!key_name
    end

    Config = Data.define(
      :mode,
      :scan,
      :threats,
      :scan_sqli,
      :scan_xss,
      :detect_mask,
      :ignore_params,
      :ignore_params_lookup,
      :ignore_headers,
      :ignore_headers_lookup,
      :scan_cookie_names,
      :max_value_bytes,
      :path_decode_depth,
      :max_depth,
      :parser_errors,
      :notifier,
      :notifier_errors,
      :notify_skipped,
      :skipped_inputs
    ) do
      def self.build(
        mode: :report,
        scan: DEFAULT_SCAN,
        threats: DEFAULT_THREATS,
        ignore_params: DEFAULT_IGNORE_PARAMS,
        ignore_headers: DEFAULT_IGNORE_HEADERS,
        scan_cookie_names: false,
        max_value_bytes: DEFAULT_MAX_VALUE_BYTES,
        max_depth: DEFAULT_MAX_DEPTH,
        path_decode_depth: DEFAULT_PATH_DECODE_DEPTH,
        parser_errors: :auto,
        notifier: nil,
        logger: nil,
        notifier_errors: :ignore,
        notify_skipped: true,
        skipped_inputs: :auto
      )
        raise ArgumentError, "pass either notifier: or logger:, not both" if notifier && logger

        mode = validate_mode(mode)
        scan = validate_scan(scan)
        threats = validate_threats(threats)
        ignored = normalize_param_names(ignore_params)
        ignored_headers = normalize_header_names(ignore_headers)

        new(
          mode: mode,
          scan: scan,
          threats: threats,
          scan_sqli: threats.include?(:sqli),
          scan_xss: threats.include?(:xss),
          detect_mask: detect_mask_for(threats),
          ignore_params: ignored,
          ignore_params_lookup: lookup_for(ignored),
          ignore_headers: ignored_headers,
          ignore_headers_lookup: lookup_for(ignored_headers),
          scan_cookie_names: !!scan_cookie_names,
          max_value_bytes: positive_integer!(max_value_bytes, :max_value_bytes),
          path_decode_depth: bounded_non_negative_integer!(path_decode_depth, :path_decode_depth, MAX_PATH_DECODE_DEPTH),
          max_depth: non_negative_integer!(max_depth, :max_depth),
          parser_errors: validate_parser_errors(parser_errors),
          notifier: notifier || build_notifier(logger),
          notifier_errors: validate_notifier_errors(notifier_errors),
          notify_skipped: !!notify_skipped,
          skipped_inputs: validate_skipped_inputs(skipped_inputs)
        )
      end

      def scan_query?   = scan.include?(:query)
      def scan_params?  = scan.include?(:params)
      def scan_path?    = scan.include?(:path)
      def scan_headers? = scan.include?(:headers)
      def scan_cookies? = scan.include?(:cookies)
      def scan_both_threats? = scan_sqli && scan_xss
      def notifier_active? = !notifier.equal?(NOOP_NOTIFIER)

      def env_only_scan? = !scan_params? && !scan_cookies?

      def parser_error_policy
        return mode == :block ? :block : :report if parser_errors == :auto

        parser_errors
      end

      def skipped_input_policy
        return mode == :block ? :block : :report if skipped_inputs == :auto

        skipped_inputs
      end

      def ignore_param?(key) = ignore_params_lookup.key?(key.to_s.downcase)
      def ignore_header?(normalized_key) = ignore_headers_lookup.key?(normalized_key)

      def self.normalize_param_names(values)
        Array(values).compact.map { |value| value.to_s.downcase }.uniq.freeze
      end

      def self.normalize_header_names(values)
        Array(values).compact.map { |value| value.to_s.downcase }.uniq.freeze
      end

      def self.lookup_for(values)
        values.each_with_object({}) { |key, index| index[key] = true }.freeze
      end

      def self.positive_integer!(value, name)
        integer = Integer(value)
        return integer if integer.positive?

        raise ArgumentError, "#{name} must be positive"
      end

      def self.non_negative_integer!(value, name)
        integer = Integer(value)
        return integer if integer >= 0

        raise ArgumentError, "#{name} must be >= 0"
      end

      def self.bounded_non_negative_integer!(value, name, max)
        integer = non_negative_integer!(value, name)
        return integer if integer <= max

        raise ArgumentError, "#{name} must be <= #{max}"
      end

      def self.validate_mode(value)
        mode = value.to_sym
        return mode if VALID_MODES.include?(mode)

        raise ArgumentError, "mode must be one of: #{VALID_MODES.join(", ")}"
      end

      def self.validate_scan(value)
        scan = Array(value).map(&:to_sym).uniq.freeze
        unknown = scan - VALID_SCAN
        return scan if unknown.empty?

        raise ArgumentError, "scan contains unknown locations: #{unknown.join(", ")}"
      end

      def self.validate_threats(value)
        threats = Array(value).map(&:to_sym).uniq.freeze
        unknown = threats - VALID_THREATS
        raise ArgumentError, "threats must include at least one of: #{VALID_THREATS.join(", ")}" if threats.empty?
        return threats if unknown.empty?

        raise ArgumentError, "threats contains unknown types: #{unknown.join(", ")}"
      end

      def self.detect_mask_for(threats)
        (threats.include?(:sqli) ? 1 : 0) | (threats.include?(:xss) ? 2 : 0)
      end

      def self.validate_parser_errors(value)
        mode = value.to_sym
        return mode if VALID_PARSER_ERRORS.include?(mode)

        raise ArgumentError, "parser_errors must be one of: #{VALID_PARSER_ERRORS.join(", ")}"
      end

      def self.validate_notifier_errors(value)
        mode = value.to_sym
        return mode if VALID_NOTIFIER_ERRORS.include?(mode)

        raise ArgumentError, "notifier_errors must be one of: #{VALID_NOTIFIER_ERRORS.join(", ")}"
      end

      def self.validate_skipped_inputs(value)
        mode = value.to_sym
        return mode if VALID_SKIPPED_INPUTS.include?(mode)

        raise ArgumentError, "skipped_inputs must be one of: #{VALID_SKIPPED_INPUTS.join(", ")}"
      end

      def self.build_notifier(logger)
        if logger
          ->(event, payload) {
            logger.warn(
              "[rack-libinjection] #{event} type=#{payload[:type]} " \
              "path=#{payload[:path]} #{payload[:location]}=#{payload[:key]}"
            )
          }
        elsif defined?(::ActiveSupport::Notifications)
          ->(event, payload) { ::ActiveSupport::Notifications.instrument(event, payload) }
        else
          NOOP_NOTIFIER
        end
      end
    end

    attr_reader :app, :config

    def initialize(app, **options)
      @app    = app
      @config = Config.build(**options)
    end

    def mode            = config.mode
    def scan            = config.scan
    def threats         = config.threats
    def ignore_params   = config.ignore_params
    def max_value_bytes = config.max_value_bytes
    def max_depth       = config.max_depth
    def path_decode_depth = config.path_decode_depth
    def parser_errors   = config.parser_errors
    def notifier        = config.notifier

    def call(env)
      return app.call(env) if mode == :off

      context = nil
      attacks = nil

      if config.env_only_scan?
        context = env
        attacks = collect_attacks_from_env(env)
      else
        context = ::Rack::Request.new(env)
        attacks = collect_attacks(context)
      end

      env[ATTACK_ENV_KEY] = attacks

      if attacks.any?
        notify_attacks(context, attacks)
        return forbidden_response if mode == :block
      end

      app.call(env)
    rescue ParserBlocked
      env[ATTACK_ENV_KEY] = []
      forbidden_response
    end

    private

    def collect_attacks(req)
      attacks = []

      scan_query_into(attacks, req, req) if config.scan_query?
      scan_path_into(attacks, req.path.to_s, req) if config.scan_path?
      scan_headers_into(attacks, req.env, req) if config.scan_headers?
      scan_cookies_into(attacks, req, req) if config.scan_cookies?
      scan_params_into(attacks, req, req) if config.scan_params?

      attacks
    rescue ::LibInjection::ParserError => e
      handle_parser_error(req, e)
      []
    end

    def collect_attacks_from_env(env)
      attacks = []

      scan_query_value_into(attacks, env["QUERY_STRING"].to_s, env) if config.scan_query?
      scan_path_into(attacks, env["PATH_INFO"].to_s, env) if config.scan_path?
      scan_headers_into(attacks, env, env) if config.scan_headers?

      attacks
    rescue ::LibInjection::ParserError => e
      handle_parser_error(env, e)
      []
    end

    def scan_query_into(attacks, req, context)
      scan_query_value_into(attacks, req.query_string.to_s, context)
    end

    def scan_query_value_into(attacks, query, context)
      return if query.empty?

      scan_url_encoded_string_into(attacks, query, location: :query, key: "query", key_name: false, context: context, plus_as_space: true)
    end

    def scan_path_into(attacks, path, context)
      scan_path_value_into(attacks, path, key: "path", context: context)
      scan_path_segments_into(attacks, path, context)
    end

    def scan_path_segments_into(attacks, path, context)
      path = path.b
      start = 0
      segment_index = 0
      bytes = path.bytesize

      loop do
        slash = path.index("/", start) || bytes
        if slash > start
          segment = path.byteslice(start, slash - start)
          scan_path_value_into(attacks, segment, key: "path[#{segment_index}]", context: context)
          segment_index += 1
        end

        break if slash >= bytes

        start = slash + 1
      end
    end

    def scan_path_value_into(attacks, value, key:, context:)
      scan_url_encoded_string_into(attacks, value, location: :path, key: key, key_name: false, context: context, plus_as_space: false)
    end

    def scan_params_into(attacks, req, context)
      walk_into(attacks, req.params, location: :params, path: +"", depth: 0, context: context)
    rescue *PARAMETER_ERRORS => e
      handle_parser_error(context, e)
    end

    def scan_headers_into(attacks, env, context)
      env.each do |key, value|
        name = header_name(key)
        next unless name
        next if config.ignore_header?(name)

        scan_string_into(attacks, value.to_s, location: :headers, key: name, key_name: false, context: context)
      end
    end

    def scan_cookies_into(attacks, req, context)
      req.cookies.each do |key, value|
        key_s = key.to_s
        next if config.ignore_param?(key_s)

        scan_string_into(attacks, key_s, location: :cookies, key: key_s, key_name: true, context: context) if config.scan_cookie_names
        scan_string_into(attacks, value.to_s, location: :cookies, key: key_s, key_name: false, context: context)
      end
    rescue *PARAMETER_ERRORS => e
      handle_parser_error(context, e)
    end

    def header_name(key)
      return "content-type" if key == "CONTENT_TYPE"
      return "content-length" if key == "CONTENT_LENGTH"
      return unless key.start_with?("HTTP_")

      key.byteslice(5, key.bytesize - 5).tr("_", "-").downcase
    end

    def request_meta(req)
      { method: req.request_method, path: req.path, ip: req.ip }
    end

    def request_meta_from_env(env)
      {
        method: env["REQUEST_METHOD"].to_s,
        path: env["PATH_INFO"].to_s,
        ip: env["REMOTE_ADDR"].to_s
      }
    end

    def meta_hash?(context)
      context.is_a?(Hash) && context.key?(:method) && context.key?(:path) && context.key?(:ip)
    end

    def meta_for(context)
      return context if meta_hash?(context)
      return request_meta_from_env(context) if context.is_a?(Hash)

      request_meta(context)
    end

    def notify_attacks(context, attacks)
      return unless config.notifier_active?

      meta = meta_for(context)
      attacks.each { |attack| notify(EVENT_NAME, attack.to_h.merge(meta)) }
    end

    def notify_error(context, error)
      return unless config.notifier_active?

      meta = meta_for(context)
      notify(ERROR_EVENT, meta.merge(error: error.class.name, message: error.message))
    end

    def notify_skipped(context, reason:, location:, key:, bytes: nil, limit: nil)
      return unless config.notify_skipped && config.notifier_active?

      meta = meta_for(context)
      notify(
        SKIPPED_EVENT,
        meta.merge(type: :skipped, reason: reason, location: location, key: key, bytes: bytes, limit: limit)
      )
    end

    def notify(event, payload)
      notifier.call(event, payload)
    rescue StandardError
      raise if config.notifier_errors == :raise

      nil
    end

    def handle_parser_error(context, error)
      case config.parser_error_policy
      when :raise
        raise error
      when :block
        notify_error(context, error)
        raise ParserBlocked
      else
        notify_error(context, error)
      end
    end

    def handle_skipped_input(context, reason:, location:, key:, bytes: nil, limit: nil)
      case config.skipped_input_policy
      when :block
        notify_skipped(context, reason: reason, location: location, key: key, bytes: bytes, limit: limit)
        raise ParserBlocked
      when :report
        notify_skipped(context, reason: reason, location: location, key: key, bytes: bytes, limit: limit)
      else
        nil
      end
    end

    def forbidden_response
      [403, FORBIDDEN_HEADERS.dup, FORBIDDEN_BODY]
    end

    def walk_into(attacks, value, location:, path:, depth:, context:)
      if depth > max_depth
        handle_skipped_input(context, reason: :max_depth, location: location, key: path, limit: max_depth)
        return
      end

      case value
      when Hash
        value.each do |key, child|
          key_s = key.to_s
          next if config.ignore_param?(key_s)

          child_path = path.empty? ? key_s : "#{path}.#{key_s}"
          scan_string_into(attacks, key_s, location: location, key: child_path, key_name: true, context: context)
          walk_into(attacks, child, location: location, path: child_path, depth: depth + 1, context: context)
        end
      when Array
        value.each_with_index do |child, index|
          child_path = "#{path}[#{index}]"
          walk_into(attacks, child, location: location, path: child_path, depth: depth + 1, context: context)
        end
      when String
        scan_string_into(attacks, value, location: location, key: path, key_name: false, context: context)
      else
        scan_uploaded_filename_into(attacks, value, location: location, key: path, context: context)
      end
    end

    def scan_uploaded_filename_into(attacks, value, location:, key:, context:)
      filename = if value.respond_to?(:original_filename)
                   value.original_filename
                 elsif value.respond_to?(:filename)
                   value.filename
                 end
      return unless filename.is_a?(String)

      scan_string_into(attacks, filename, location: location, key: "#{key}.filename", key_name: false, context: context)
    end

    def scan_url_encoded_string_into(attacks, value, location:, key:, key_name:, context:, plus_as_space:)
      bytes = value.bytesize
      return if bytes.zero?

      if bytes > max_value_bytes
        handle_skipped_input(context, reason: :max_value_bytes, location: location, key: key, bytes: bytes, limit: max_value_bytes)
        return
      end

      match = ::LibInjection.detect_url_encoded_raw(value, path_decode_depth, plus_as_space, config.detect_mask)
      return unless match

      attacks << Attack.new(
        type: match[0],
        location: location,
        key: key,
        key_name: key_name,
        fingerprint: match[1],
        bytes: bytes
      )
    end

    def scan_string_into(attacks, value, location:, key:, key_name:, context:)
      bytes = value.bytesize
      return if bytes.zero?

      if bytes > max_value_bytes
        handle_skipped_input(context, reason: :max_value_bytes, location: location, key: key, bytes: bytes, limit: max_value_bytes)
        return
      end

      match = detect_value(value)
      return unless match

      attacks << Attack.new(
        type: match[0],
        location: location,
        key: key,
        key_name: key_name,
        fingerprint: match[1],
        bytes: bytes
      )
    end

    def detect_value(value)
      if config.scan_both_threats?
        ::LibInjection.detect_raw(value)
      elsif config.scan_sqli
        fingerprint = ::LibInjection.sqli_fingerprint(value)
        fingerprint && [:sqli, fingerprint]
      elsif ::LibInjection.xss?(value)
        [:xss, nil]
      end
    end
  end
end
