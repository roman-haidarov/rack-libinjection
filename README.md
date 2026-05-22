# rack-libinjection

`rack-libinjection` is a small native Ruby binding plus Rack middleware for
[libinjection](https://github.com/libinjection/libinjection).

It adds a tokenizer/fingerprint-based SQLi/XSS **signal layer** to Rack and
Rails applications. It is report-only by default.

## Important scope note

This is not a full WAF. The middleware scans only the configured Rack surfaces.
The default is:

- parsed Rack params (`scan: [:params]`)

Optional surfaces are available for raw query strings, path, headers, and cookies:

- `scan: [:query]` for a fast raw query-string signal that avoids Rack nested params parsing
- `scan: [:params, :path, :headers, :cookies]` for semantic params plus other Rack surfaces

The middleware can scan both SQLi and XSS signals by default, or only one class through `threats: [:sqli]` / `threats: [:xss]`. Path and raw-query values are decoded up to `path_decode_depth` times for detection inside the native extension, avoiding Ruby `gsub`/regex allocation on this hot path. Query/path/header-only configurations are scanned directly from the Rack env without constructing `Rack::Request`; params and cookies still use Rack parsers. Header
scanning skips common low-signal protocol/browser headers by default through
`ignore_headers`. Cookie values are scanned when `:cookies` is enabled; cookie
names are skipped unless `scan_cookie_names: true` is configured. In `mode: :block`, native/Rack parser errors fail closed by default through `parser_errors: :auto`, and values skipped by `max_value_bytes` / `max_depth` fail closed by default through `skipped_inputs: :auto`.

Raw JSON body scanning is not part of the current middleware. JSON bodies,
large request bodies, multipart file contents, and application-specific decoding
need separate design. See [GET_STARTED.md](GET_STARTED.md) before deploying.

## Usage

All installation, middleware configuration, low-level API examples, vendoring,
system-library mode, GVL notes, threat model, and operational guidance live in
[GET_STARTED.md](GET_STARTED.md).

## What this is

- A native binding to vendored `libinjection` `v4.0.0`.
- A Rack/Rails middleware that emits attack signals for configured request
  surfaces.
- A diagnostic API for SQLi fingerprints, parser contexts, SQL tokens, XSS
  contexts, and HTML5 tokens.
- A small signal layer that can feed logs, notifications, or `Rack::Attack`-style
  scoring.

## What this is not

- Not a full WAF.
- Not a replacement for Rails escaping, bind params, CSP, authorization, or
  upstream WAF/rate-limit protections.
- Not a promise to catch every SQLi/XSS payload.
- Not enabled in blocking mode by default.
- Not a JSON-body scanner yet.

## Native dependency

The default build uses pinned, vendored `libinjection` sources. Source checkouts
can regenerate or verify the vendored tree through `script/vendor_libs.rb`; see
[GET_STARTED.md](GET_STARTED.md) for commands and system-library mode.

## Security policy

Report suspected vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

The Ruby gem is MIT-licensed. The vendored upstream `libinjection` sources are
BSD-3-Clause licensed and included as `LICENSE-libinjection.txt`.
