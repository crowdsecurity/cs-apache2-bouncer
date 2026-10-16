# Fuzzing

Three targets, one per parser that reads something we did not write. They are a
developer tool, not part of `make check`: libFuzzer needs clang, and the
targets run until you stop them. CI does not run them.

| target | parser | what it asserts beyond "did not crash" |
|---|---|---|
| `fuzz_verdict` | `crowdsec_appsec_parse` | every emitted header name, header value, cookie and content type passes the sanitisers; counts within cap; `100 <= http_status <= 599`; a non-zero `body_len` has a body |
| `fuzz_stream` | `crowdsec_stream_parse` | family is 4 or 6; prefix length in range for it; **the address is masked to its prefix**; bytes past the family width are zero; additions have a positive duration; the result encodes to a well-formed key |
| `fuzz_hdr` | the three sanitisers | nothing containing CR, LF or NUL is ever accepted; the classes nest (token ⊂ target ⊂ field content) |

The assertions are the point. A target that only checks for crashes says
nothing about whether a malformed verdict could inject a second header, so the
post-conditions encode the properties the rest of the module relies on.

## Build

```
autoreconf -fi
CC=clang ./configure --with-apxs=/usr/bin/apxs2 --enable-fuzzing
make fuzz
```

`configure` fails early if the compiler has no libFuzzer, rather than at link
time. On Debian and Ubuntu, `apt install clang` is enough.

## Run

```
ASAN_OPTIONS=quarantine_size_mb=16 \
  ./fuzz/fuzz_verdict fuzz/corpus/verdict -max_total_time=60 -rss_limit_mb=256
```

**Bound the quarantine.** These are ASan builds, and ASan holds freed chunks in
a quarantine that defaults to 256MB, so `-rss_limit_mb=256` otherwise reports
an out-of-memory that has nothing to do with the parser. Measured: 300k runs of
one 36-byte input peak at 345MB with the default quarantine and 60MB with
`quarantine_size_mb=16`. With it bounded, a 60-second run of each target sits
at 72-115MB, so a 256MB limit has real headroom and a genuine single-input
blowup would still trip it.

Reference numbers from a 60-second run each (clang 21, 4 vCPU):

| target | executions | peak RSS |
|---|---|---|
| `fuzz_verdict` | 5.8M | 115MB |
| `fuzz_stream` | 6.0M | 112MB |
| `fuzz_hdr` | 13.0M | 72MB |

## Corpus

`fuzz/corpus/<target>/` holds seeds in the shapes the engine actually sends:
allow, ban, captcha, a full challenge with cookies and headers, a 307 with a
Location, an empty stream, single-IP and range decisions in both families, an
out-of-scope `Country` decision and an already-expired one, and the boundary
bytes for the sanitisers. libFuzzer writes new coverage into the directory you
pass, so point it at a scratch copy if you want the committed seeds left alone.

## Checking a target still bites

A fuzz target that cannot catch a known defect is decoration. Both JSON targets
were validated by planting a bug and confirming they fail:

- removing the `crowdsec_hdr_value_ok` check in `dup_header_safe` is caught by
  `fuzz_verdict` as `Assertion 'crowdsec_hdr_value_ok(v.cookies[j])' failed`
- replacing `crowdsec_ip_mask` with a plain copy in `crowdsec_cidr_parse` is
  caught by `fuzz_stream` on the prefix-masking assertion

Worth repeating after changing either parser.

## Known limit

`fuzz_verdict` cannot catch a narrowing bug in `http_status`, because it can
only see the value the parser stored. A 32-bit truncation of 4294967496 to 200
looks valid from here. That case is covered by `test/unit/t_verdict.c` instead,
which asserts the parse is *rejected*.
