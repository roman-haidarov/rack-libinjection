# Security policy

`rack-libinjection` is a security signal layer, so vulnerability reports are
welcome even for edge cases that look minor.

## Supported versions

The project is pre-1.0. Security fixes are applied to the latest released
version only until a stable compatibility policy exists.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability.

Send a report to:

- `romanhajdarov@gmail.com`

Include:

- affected version / commit;
- Ruby, Rack, and OS versions;
- minimal reproduction;
- whether the issue is in the native binding, Rack middleware, vendoring, or
  documentation;
- expected vs actual behavior.

## Scope

Useful reports include:

- crashes or memory-safety issues in the native extension;
- incorrect use of vendored libinjection sources;
- middleware bypasses caused by this gem's Rack integration;
- false claims in documentation that can lead to unsafe deployment;
- unsafe default behavior around notifications, blocking mode, or skipped input.

Bypasses in upstream `libinjection` itself should also be reported upstream, but
it is still useful to notify this project when the Rack integration makes them
worse or hides the limitation.

## Native hardening expectations

The native extension is expected to tolerate empty strings, binary strings,
invalid UTF-8 byte sequences, null bytes, and large inputs without crashing.
Public low-level scans copy large inputs before releasing the GVL, so the C
scanner does not read directly from a Ruby `String` buffer while Ruby code may
mutate the same object from another thread. Copied native buffers are released
through `rb_ensure` cleanup paths.

The project includes a `security:smoke` task with random/binary inputs and a CI
sanitizer job for AddressSanitizer/UBSan builds. These checks are not a
replacement for upstream libinjection fuzzing, but regressions in the Ruby
binding or middleware integration should be caught here.

The binding scans bytes. It does not perform Unicode normalization or transcode
UTF-16/UTF-32 payloads into UTF-8. Applications that accept non-UTF-8 text must
normalize before scanning if they expect semantic text detection rather than raw
byte scanning.

## Fail-closed behavior in blocking mode

Vendored libinjection v4 can return parser errors, and Rack can raise parameter/cookie parser errors before values are available for semantic scanning. The middleware exposes `parser_errors:` so applications can choose report, block, or raise behavior. The default `:auto` policy reports parser errors in report mode and blocks them in block mode.

Inputs beyond `max_value_bytes` or deeper than `max_depth` are not scanned. The middleware exposes `skipped_inputs:` so applications can choose report, block, or allow behavior. The default `:auto` policy reports skipped input in report mode and blocks it in block mode.
