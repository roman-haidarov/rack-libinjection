# Changelog

## Unreleased

### Security / hardening

- Added explicit Rack middleware parser-error policy. `parser_errors: :auto` now reports native libinjection and known Rack parameter/cookie parser errors in report mode and fails closed in block mode; `:report`, `:block`, and `:raise` are available for explicit behavior.
- Added explicit skipped-input policy. `skipped_inputs: :auto` reports `max_value_bytes` / `max_depth` skips in report mode and fails closed in block mode; `:report`, `:block`, and `:allow` are available for explicit behavior.
- Narrowed the default ignored params to `authenticity_token`; sensitive values such as `password` are scanned by default while raw values remain absent from notifications.
- Public low-level scans that release the GVL now copy large input strings into
  a temporary C buffer before scanning. This avoids reading directly from a Ruby
  `String` buffer while another Ruby thread could mutate/reallocate it.
- `RB_GC_GUARD` placement and native scan cleanup were tightened. Public
  low-level scan methods now release copied C buffers through `rb_ensure`, so
  async Ruby exceptions cannot skip native buffer cleanup.
- SQLi fingerprint buffer sizing is now tied to the vendored libinjection
  struct field instead of a standalone magic number.
- Added native edge-case tests for empty strings, nil input, invalid UTF-8,
  binary/null-byte payloads, UTF-16 byte input, large no-GVL inputs, and invalid
  option values.
- Added `security:smoke` random/binary-input checks and an AddressSanitizer/UBSan
  CI job.

### Fixed

- `:path` scanning now checks individual path segments when the full path is not
  classified. This keeps SQLi-like path payloads such as
  `/items/1 OR 1=1--` detectable instead of letting the route prefix hide the
  payload from libinjection. Percent-encoded path values are decoded up to
  `path_decode_depth` times for this fallback; the default is `2`.
- Empty attack lists stored in `rack.libinjection.attacks` are now mutable per
  request instead of a shared frozen array.
- Header scanning now supports `ignore_headers` and skips common low-signal
  protocol/browser headers by default.
- Cookie name scanning is disabled by default and can be enabled with
  `scan_cookie_names: true`; cookie values are still scanned when `:cookies` is
  enabled.

### Performance

- Added a native URL-decoded scan primitive, `LibInjection.detect_url_encoded_raw(input, depth, plus_as_space, threat_mask)`, used by Rack `:query` and `:path` surfaces. It scans raw, decoded-once, and decoded-twice variants without Ruby `gsub`, Oniguruma, or intermediate decoded Ruby strings. Small decoded buffers now use stack allocation; heap allocation is reserved for larger decoded inputs.
- `scan: [:query]`, `scan: [:path]`, and `scan: [:query, :path, :headers]` can now run directly from the Rack env without constructing `Rack::Request`; `:params` and `:cookies` still use Rack parsers to preserve their semantics.
- Added `scan: [:query]`, a fast raw query-string surface that scans the query string and decoded variants without invoking Rack nested params parsing.
- Added `threats: [:sqli]` / `threats: [:xss]` middleware modes for deployments that intentionally want to skip one native detector on hot paths.
- Attack notifications and skipped/error notifications now build request metadata lazily and do no payload work when the notifier is the built-in no-op.
- Header name normalization no longer uses an unbounded per-middleware cache. Path/query decoding now stays in C and is skipped when the value has no URL-encoded candidate bytes.
- Added `LibInjection.detect_raw` — a single native primitive that runs SQLi
  and XSS checks in one Ruby->C call and short-circuits XSS when SQLi is
  already detected. Returns the minimum data needed (`nil`, `[:sqli, fp]`,
  or `[:xss, nil]`) with no Result/Hash allocation.
- Native scans now release the GVL for inputs >= `LI_NOGVL_THRESHOLD` bytes
  (default 1024). The extension uses `rb_nogvl(..., RB_NOGVL_OFFLOAD_SAFE)`
  when the Ruby headers provide that flag, and falls back to
  `rb_thread_call_without_gvl` on older headers.
- `Rack::LibInjection` middleware rewritten on top of a mutable accumulator:
  no more per-level `flat_map`, no more `path + [key]` allocations, no more
  intermediate hashes per match. Path keys are now built as plain `String`s.
- Middleware now uses `LibInjection.detect_raw` instead of `sqli_fingerprint`
  + `xss?`, halving the number of Ruby->C boundaries per scanned string.

### Middleware behavior

- Notification event names now use dotted namespaces:
  - `rack.libinjection.attack`
  - `rack.libinjection.error`
  - `rack.libinjection.skipped`
- Supported scan locations are now explicit: `:query`, `:params`, `:path`, `:headers`,
  and `:cookies`. Default remains `scan: [:params]`.
- Middleware emits skipped-input telemetry for values skipped because of
  `max_value_bytes` or `max_depth` when `notify_skipped: true`; block mode fails closed for skipped input by default.
- Middleware no longer rescues `StandardError` around scanning. It catches
  `LibInjection::ParserError` and known Rack parameter parsing errors, emits an
  error event, and lets unrelated exceptions propagate.
- Notifier exceptions are isolated by default (`notifier_errors: :ignore`) so a
  reporting subscriber cannot accidentally turn a request into a 500. Use
  `notifier_errors: :raise` in tests/development when desired.
- Explicit `logger:` now wins over ActiveSupport auto-detection. Passing both
  `logger:` and `notifier:` remains an `ArgumentError`.
- `Config.build` now validates scan locations and notifier error mode.
- Uploaded file names are scanned when upload objects expose `original_filename`
  or `filename`; file contents are not scanned.

### Native / vendoring

- Minimum Ruby version is **3.3**. Ruby versions whose headers do not expose
  `RB_NOGVL_OFFLOAD_SAFE` still build through the classic no-GVL fallback; they
  just do not get the Fiber Scheduler offload-safe hint.
- System libinjection mode now verifies that the runtime libinjection version is
  exactly `4.0.0`, because this binding uses v4 diagnostic structs and token
  fields.
- The vendored manifest no longer includes a self-hash. Verification now relies
  on the pinned upstream archive SHA-256 plus local tree checksum.
- The vendor script now downloads with `Net::HTTP`, explicit timeouts, retry
  handling, redirect handling, and streaming writes instead of `URI.open` and
  `remote.read`.
- `extconf.rb` no longer auto-downloads vendored native sources during build; missing vendored sources fail with an explicit instruction to run `script/vendor_libs.rb`.

### Docs / project hygiene

- Added `SECURITY.md` for private vulnerability reporting.
- README now states the scan surface and JSON-body limitation at the top.
- GET_STARTED now includes a threat model, skipped input behavior, PII notes,
  GVL/offload notes, notifier hot-path warning, and system-library version guard.
- Added explicit BSD-3 attribution for vendored libinjection.

## 0.1.0

- Initial native binding for libinjection v4.0.0.
- Added `LibInjection.sqli?`, `LibInjection.sqli_fingerprint`, `LibInjection.xss?`, and `LibInjection.detect`.
- Added table-driven diagnostic native API: `sqli_result`, `sqli_contexts`, `sqli_tokens`, `sqli_fingerprint_for`, `xss_result`, `xss_contexts`, and `html5_tokens`.
- Added `Rack::LibInjection` middleware in report/block/off modes.
- Added pinned `script/vendor_libs.rb` vendoring workflow.
