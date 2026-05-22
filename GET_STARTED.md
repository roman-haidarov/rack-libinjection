# Get started

## Install

Add the gem to your `Gemfile`:

```ruby
# Gemfile
gem "rack-libinjection"
```

The published gem should ship vendored `libinjection` sources, so users install
it with a normal `bundle install`.

For source checkouts, vendor pinned upstream sources explicitly before building.
The extension does not auto-download native code during `extconf.rb`:

```bash
bundle install
bundle exec rake vendor
bundle exec rake compile
bundle exec rake test
```

## Rails middleware

Start in report-only mode:

```ruby
# config/application.rb
config.middleware.use Rack::LibInjection, mode: :report
```

Full configuration example:

```ruby
# config/application.rb
config.middleware.use Rack::LibInjection,
  mode: :report,
  scan: [:params],
  threats: [:sqli, :xss],
  max_value_bytes: 8192,
  max_depth: 8,
  path_decode_depth: 2,
  ignore_params: %w[authenticity_token],
  ignore_headers: Rack::LibInjection::DEFAULT_IGNORE_HEADERS,
  scan_cookie_names: false,
  parser_errors: :auto,
  notify_skipped: true,
  skipped_inputs: :auto,
  notifier_errors: :ignore
```

Start in `:report`; switch to `:block` only after observing false positives.

### Modes

- `:report` — detect and notify, then continue request processing.
- `:block` — return `403` when at least one attack signal is detected. With the default `parser_errors: :auto` and `skipped_inputs: :auto`, Rack/native parser errors and limit-skipped input also fail closed.
- `:off` — no scanning.

The middleware stores attack records in:

```ruby
request.env["rack.libinjection.attacks"]
```

Each record has:

```ruby
{
  type: :sqli,             # or :xss
  location: :params,       # :query, :params, :path, :headers, or :cookies
  key: "search.q",
  key_name: false,         # true when the signal came from a param/cookie key
  fingerprint: "s&1UE",   # SQLi only
  bytes: 23
}
```

## Scanning model

The default scan surface is deliberately narrow:

```ruby
scan: [:params]
```

Supported scan locations:

- `:query` — raw Rack query string plus decoded variants. This is the fastest WAF-style signal surface and avoids Rack nested params parsing; URL decoding is performed in the native extension to avoid Ruby `gsub`/regex allocation, but this surface does not provide semantic per-param keys;
- `:params` — parsed Rack params, including query/form params as provided by Rack;
- `:path` — `request.path`, with a segment fallback so `/items/1 OR 1=1--` is scanned as both the full path and individual path segments. Percent-encoded path values are decoded inside the native extension up to `path_decode_depth` times for detection; the default is `2` to catch common double-encoding attempts.
- `:headers` — Rack HTTP headers from `env`, except names in `ignore_headers`;
- `:cookies` — parsed Rack cookie values. Cookie names are skipped by default and can be enabled with `scan_cookie_names: true`.

The middleware scans predictable, bounded input only:

- string values inside parsed params, cookies, and non-ignored headers;
- string keys inside params hashes;
- multipart upload filenames when an upload object exposes `original_filename`
  or `filename`;
- values up to `max_value_bytes`;
- nested structures up to `max_depth`;
- ignored params and ignored headers are skipped by exact normalized name. The default ignored param list is intentionally narrow (`authenticity_token` only); sensitive values such as `password` are scanned, but raw values are not emitted in attack notifications.

Threat classes are configurable:

```ruby
threats: [:sqli, :xss] # default
threats: [:sqli]       # skip the XSS state machine on clean strings
threats: [:xss]        # skip SQLi fingerprinting
```

Use single-threat mode only when the missing class is covered elsewhere. The main performance reason is that clean strings otherwise run both SQLi fingerprinting and the XSS state machine.

For raw query/path scanning, `path_decode_depth: 0` scans only the raw value. Depth `1` adds one percent-decoded pass, and depth `2` adds a second pass for common double-encoding attempts. The value is hard-capped at `Rack::LibInjection::MAX_PATH_DECODE_DEPTH` to avoid accidental CPU-heavy configurations. Query decoding treats `+` as a space; path decoding keeps `+` literal. Malformed percent escapes are kept literal inside the native decoder instead of raising through Ruby `gsub`/regex machinery.

Header scanning is intentionally noisy if every header is scanned. By default the
middleware ignores low-signal protocol/browser headers such as `Accept`, `Host`,
`Content-Type`, and `Content-Length`. Override `ignore_headers: []` if you really
want every Rack header scanned.

Cookie names are also skipped by default because names are often application
controlled and can produce false positives (`session_or_token`, feature flags,
etc.). Enable `scan_cookie_names: true` only if cookie names are attacker
controlled or security-relevant in your application.

There is deliberately no hidden “lazy suspicious prefilter” before
libinjection. That avoids creating a second bypass-prone mini-WAF layer.

### Parser error policy

Vendored libinjection v4 returns parser errors instead of aborting. The Rack middleware treats those errors explicitly:

```ruby
parser_errors: :auto   # default: report in :report mode, block in :block mode
parser_errors: :report # notify and allow
parser_errors: :block  # notify and return 403
parser_errors: :raise  # re-raise LibInjection::ParserError
```

For blocking deployments, `:auto` fails closed: native libinjection parser errors and known Rack parameter/cookie parser errors are treated like blocked requests.


Raw JSON body scanning is intentionally not part of the current middleware.
Rack body rewind, large request bodies, multipart file contents, nested JSON
depth, and PII-safe logging need separate design. If your API is JSON-only,
keep this limitation visible in your threat model.

### Skipped input notifications

Input skipped because of safety limits is observable through:

```ruby
rack.libinjection.skipped
```

The payload includes `reason`, `location`, `key`, `bytes`, and `limit` when
available. This is intentionally separate from attack notifications: a skipped
large/deep value is not an attack by itself, but it is useful telemetry when
someone tries to hide payloads behind configured limits.

Skipped input policy is explicit:

```ruby
skipped_inputs: :auto   # default: report in :report mode, block in :block mode
skipped_inputs: :report # notify and allow
skipped_inputs: :block  # notify and return 403
skipped_inputs: :allow  # allow silently
```

Disable skipped telemetry if it is too noisy while keeping the same allow/block
policy:

```ruby
config.middleware.use Rack::LibInjection, notify_skipped: false
```

## Notifications

If `ActiveSupport::Notifications` is loaded and no explicit `logger:` or
`notifier:` is provided, the middleware emits:

```ruby
ActiveSupport::Notifications.subscribe("rack.libinjection.attack") do |_name, _start, _finish, _id, payload|
  Rails.logger.warn(payload.inspect)
end
```

You can also pass a custom notifier:

```ruby
config.middleware.use Rack::LibInjection,
  notifier: ->(event, payload) { SecurityEvents.write(event, payload) }
```

Explicit `logger:` wins over the ActiveSupport auto-detection:

```ruby
config.middleware.use Rack::LibInjection, logger: Rails.logger
```

`Rack::LibInjection` calls `notifier.call(...)` synchronously inside the
middleware. A slow subscriber slows down the entire request. Do not perform
blocking IO inside a subscriber. If you need to persist attack signals to Redis,
a database, or an external service, push to a background queue and process out
of band:

```ruby
ActiveSupport::Notifications.subscribe("rack.libinjection.attack") do |_, _, _, _, payload|
  AttackEventJob.perform_later(payload)
end
```

Notifier exceptions are ignored by default so a reporting hook cannot turn a
request into a 500. To fail closed during development or tests:

```ruby
config.middleware.use Rack::LibInjection, notifier_errors: :raise
```

The middleware also emits `rack.libinjection.error` events when Rack parameter
parsing or libinjection parser errors occur on the configured scan surface.
These are rare but useful to monitor.

## Rack::Attack integration

Keep `rack-libinjection` in report mode and score IPs yourself:

```ruby
class LibInjectionTracker
  def self.record(ip, attack)
    Rails.cache.increment("libinjection:#{ip}:score", 1, expires_in: 10.minutes)
  end

  def self.score(ip)
    Rails.cache.read("libinjection:#{ip}:score").to_i
  end
end

ActiveSupport::Notifications.subscribe("rack.libinjection.attack") do |_name, _start, _finish, _id, payload|
  LibInjectionTracker.record(payload[:ip], payload)
end

Rack::Attack.blocklist("libinjection repeat attackers") do |req|
  LibInjectionTracker.score(req.ip) > 5
end
```

## Threat model and limitations

`rack-libinjection` is a signal layer. It helps identify suspicious payloads
that reached configured Rack surfaces. It is not the control that keeps SQL or
HTML safe.

Still required:

- ActiveRecord bind params / parameterized SQL;
- output escaping and CSP;
- authorization;
- rate limiting;
- upstream WAF/reverse-proxy controls where appropriate.

Known limitations:

- detection inherits upstream `libinjection` limits and bypasses;
- only ANSI/MySQL SQLi contexts are exposed by this binding's diagnostic API;
- the middleware scans what Rack has already parsed; path values are decoded up
  to `path_decode_depth` times, but params/cookies/headers are not recursively
  decoded by this gem;
- Unicode normalization is not performed; callers that need NFC/NFKC or
  UTF-16/UTF-32 decoding must normalize before scanning;
- values beyond `max_value_bytes` and nested values deeper than `max_depth` are not scanned. In report mode they are reported as skipped input by default; in block mode they are blocked by default through `skipped_inputs: :auto`;
- JSON bodies are not scanned yet;
- path and IP in notification payloads can contain identifiers, so treat them as
  operational/security telemetry, not PII-free analytics data.

## Low-level API

```ruby
require "libinjection"

LibInjection.sqli?("1 OR 1=1--")
# => true

LibInjection.sqli_fingerprint("1 OR 1=1--")
# => "..." or nil

LibInjection.xss?("<script>alert(1)</script>")
# => true / false

LibInjection.detect("1 OR 1=1--")
# => #<data LibInjection::Result type=:sqli, detected=true, fingerprint="...">
```

### Hot-path primitive

`detect_raw` is the low-allocation primitive used internally by the Rack
middleware. It returns the minimum amount of data needed to decide what to do,
without allocating a `Result` object.

```ruby
LibInjection.detect_raw("1 OR 1=1--")
# => [:sqli, "s&1UE"]

LibInjection.detect_raw("<script>alert(1)</script>")
# => [:xss, nil]

LibInjection.detect_raw("hello")
# => nil
```

### Diagnostic API

```ruby
LibInjection.sqli_result("1 OR 1=1--")
LibInjection.sqli_contexts("1 OR 1=1--")
LibInjection.sqli_tokens("1 OR 1=1--")
LibInjection.sqli_tokens("1 OR 1=1--", fold: true)
LibInjection.sqli_fingerprint_for("1 OR 1=1--", context: :none_ansi)

LibInjection.xss_result("<script>alert(1)</script>")
LibInjection.xss_contexts("<script>alert(1)</script>")
LibInjection.html5_tokens("<script>alert(1)</script>")
```

Available native maps:

```ruby
LibInjection::SQLI_CONTEXTS
LibInjection::SQLI_QUOTES
LibInjection::SQLI_DIALECTS
LibInjection::SQLI_TOKEN_TYPES
LibInjection::HTML5_CONTEXTS
LibInjection::XSS_CONTEXTS
LibInjection::HTML5_TOKEN_TYPES
```

Parser errors from libinjection v4 are exposed as
`LibInjection::ParserError`.

## Vendored libinjection

The vendor flow pins upstream C sources by archive SHA-256 and records a tree
checksum for local verification.

```bash
ruby script/vendor_libs.rb --sync
ruby script/vendor_libs.rb --verify
```

Pinned upstream:

- libinjection `v4.0.0`
- archive SHA-256: `a69d27e3d98608df89203c4e1c00c034fe0f8c723017e4088ab53ce3ff5a9129`

The script records a tree checksum in
`ext/libinjection/vendor/libinjection/.vendored`. This catches accidental local
changes to vendored files. It is not a cryptographic signature; the upstream
archive hash above is the external integrity pin.

## System library mode

Default mode is vendored. For distro builds:

```bash
bundle config build.rack-libinjection --use-system-libinjection
# or
LIBINJECTION_USE_SYSTEM=1 bundle install
```

When system mode is used, the extension checks the runtime libinjection version
at load time and rejects versions other than `4.0.0`; the binding exposes
diagnostic structs and token fields that are tied to that upstream API.

## Concurrency and the GVL

`libinjection` scans are pure CPU work over raw bytes. They do not allocate on
the heap, do not call into the Ruby C API, and do not touch global state. That
makes them a good candidate for releasing the GVL during a scan.

For inputs of at least `LI_NOGVL_THRESHOLD` bytes (default `1024`), the native
binding releases the GVL. When the Ruby headers provide
`RB_NOGVL_OFFLOAD_SAFE`, the binding passes that flag to `rb_nogvl(...)` so a
Fiber Scheduler can treat the scan as offload-safe. On older Ruby headers that
only provide the classic no-GVL API, the extension falls back to
`rb_thread_call_without_gvl(...)`: multi-thread Puma/Sidekiq still benefit, but
there is no scheduler offload hint.

Short inputs are scanned inline under the GVL. The fixed overhead of releasing
the GVL is larger than the scan itself on small payloads, so the threshold is
conservative and should be tuned with benchmarks for specific deployments. You
can override it at build time:

```bash
bundle config build.rack-libinjection -- --with-cflags="-DLI_NOGVL_THRESHOLD=512"
```

### Memory safety contract

For public low-level scans that release the GVL, the native binding first
copies the input bytes into a temporary C buffer. That avoids reading from a
Ruby `String` buffer while another Ruby thread could mutate or reallocate the
same object. Short inputs are scanned under the GVL without a copy.

The binding scans bytes, not semantic text. It accepts `UTF-8` and
`ASCII-8BIT`/binary strings, including invalid byte sequences, as byte input. It
does not implicitly decode UTF-16/UTF-32 into UTF-8. Normalize or transcode
application text before calling the low-level API if your application accepts
non-UTF-8 encodings.

## License notes

The Ruby gem is MIT-licensed. The vendored upstream `libinjection` sources are
BSD-3-Clause licensed; the upstream license is included as
`LICENSE-libinjection.txt` in the packaged gem and
`ext/libinjection/vendor/libinjection/COPYING` in source checkouts.
