# tsf-http

HTTP from a test suite, packaged as an external Test Environment (TE)
repository.

Library:

- `tapi_http` — engine-side, built as a shared library: one request and
  the whole answer, what the response headers say about the service,
  what the endpoint lets you do to it, and a server that is wrong on
  purpose.

TE can already generate HTTP load — `tapi_wrk` does that, and better
than anything here would. This asks the other question: not how fast
the endpoint answers, but **what it answers with**.

Nearly everything that goes wrong with an HTTP service in the field is
in the response headers, and none of it is visible to a load generator
or to a browser that simply works. A missing
`Strict-Transport-Security`. A session cookie without `HttpOnly`.
`Access-Control-Allow-Origin: *` next to
`Access-Control-Allow-Credentials: true`. A `Server` header naming the
exact build. `TRACE` still answering. Each one is a line of
configuration, each one is invisible until somebody looks, and each one
is exactly the kind of thing a test should hold in place once it has
been fixed.

## Usage

Declare the repositories in an external libraries catalog and pass it
to `dispatcher.sh --external=external.yml`:

```yaml
repositories:
  - name: tsf_devtool
    url: https://github.com/interpretica-io/tsf-devtool.git
    ref: <tag>
    libs: [ tapi_devtool ]
  - name: tsf_cybersec
    url: https://github.com/interpretica-io/tsf-cybersec.git
    ref: <tag>
    libs: [ tapi_cybersec ]
  - name: tsf_http
    url: https://github.com/interpretica-io/tsf-http.git
    ref: <tag>
    libs: [ tapi_http ]
```

Bind them in `builder.conf`:

```
TE_EXT_REPO_USE([tsf_devtool], [], [tapi_devtool])
TE_EXT_REPO_USE([tsf_cybersec], [], [tapi_cybersec])
TE_EXT_REPO_USE([tsf_http], [], [tapi_http])
```

Then add `tapi_http` to `te_libs` in the suite's `meson.build`.

Requires TE with `TE_EXT_REPO` support and an **RPC** job factory
(`ta_rpcprovider` on the agent). On the agent it needs `curl`, and
`python3` as well if the test stands up an endpoint of its own.

```c
tapi_http_request_opt opt = tapi_http_request_default_opt;
tapi_http_response response;

opt.url = "https://dut.example.net/api/health";
CHECK_RC(tapi_http_request(factory, &opt, 10000, &response));

RING("status %u", response.status);
tapi_http_headers_check(&response, NULL, &report);
tapi_http_response_free(&response);
```

## One request, the whole answer

Requests are made with `curl` **on the agent**, because a test should
ask the question from where the device is rather than from the engine.
What comes back is parsed whole:

- the status, the version and the reason phrase;
- every header in the order it was sent — repeated ones included, which
  matters: two `Set-Cookie` headers are normal and two
  `Content-Security-Policy` headers are a hazard;
- the body;
- the **chain**: the status of every response including the redirects
  that led here, so a test can see `302 -> 301 -> 200` rather than just
  the end of it;
- the URL the request finished at, and whether it got there over TLS.

A reply that is an error — 404, 500 — is an answer and comes back in
`status`. The status code of `tapi_http_request()` is about whether the
question could be asked at all.

`tapi_http_wait_ready()` is the other half of that: for a service the
test has just started, it asks until something replies. Any status
counts — a 404 means it is listening.

## What the headers say

`tapi_http_headers_check()` reads a response and reports what is
missing, what is too permissive, and what says more than it should:

| Finding | Severity | When |
|---|---|---|
| `http.no-hsts` | medium | over TLS, no `Strict-Transport-Security` |
| `http.short-hsts` | low | `max-age` below the policy's floor |
| `http.no-csp` | medium | a page with no `Content-Security-Policy` |
| `http.duplicate-csp` | low | two of them |
| `http.weak-csp` | low | `unsafe-inline` or `unsafe-eval` |
| `http.no-nosniff` | low | `X-Content-Type-Options` is not `nosniff` |
| `http.framable` | low | no `X-Frame-Options` and no `frame-ancestors` |
| `http.no-referrer-policy` | info | no `Referrer-Policy` |
| `http.cookie-no-httponly` | medium | a cookie a script can read |
| `http.cookie-no-secure` | medium | over TLS, a cookie without `Secure` |
| `http.cookie-no-samesite` | low | a cookie without `SameSite` |
| `http.cors-wildcard-credentials` | high | `*` together with credentials |
| `http.cors-wildcard` | low | `Access-Control-Allow-Origin: *` |
| `http.version-banner` | low | `Server` or `X-Powered-By` names a version |

Three of these are deliberately conditional, because a finding nobody
can act on is worse than none:

- **HSTS is only checked over TLS.** A browser ignores the header on a
  plain connection, so demanding it there would be advice that changes
  nothing.
- **`Secure` on a cookie is only checked over TLS**, for the same
  reason.
- **The rendering headers apply to pages, not to APIs.** A JSON
  endpoint gets no `http.no-csp`; `tapi_http_headers_policy::kind` is
  how a test says which it has.

The cookie checks look at attributes **after the first `;`**, so a
cookie called `HttpOnly`, or one whose value contains the word, is not
mistaken for a cookie that has the flag. The banner check only fires
when the header contains a digit: a name alone is no use to anyone, and
a version number is the difference between knowing what to attack and
having to find out.

## What the endpoint allows

`tapi_http_methods_probe()` asks `OPTIONS` first, because an endpoint
that answers it has already said what it allows.

What is **sent** is `GET`, `HEAD`, `OPTIONS` and `TRACE` — the four
HTTP defines as safe, which are not allowed to have side effects.
`PUT`, `DELETE` and `PATCH` are **not sent**. They are read out of the
`Allow` header — the server's own statement — and reported on that
basis, because sending them means asking a service under test to modify
or delete something, and a scanner that does that has stopped being a
scanner.

| Finding | Severity | When |
|---|---|---|
| `http.trace-enabled` | medium | `TRACE` answers 2xx |
| `http.changing-method-allowed` | low | `Allow` lists `PUT`/`DELETE`/`PATCH` |
| `http.no-options` | info | `OPTIONS` was not answered, so the rest is unknown |

`http.no-options` exists because without an `Allow` header the *absence*
of the other findings says nothing, and a report that is silent for two
different reasons is a report that cannot be read.

## A server that is wrong on purpose

`tapi_http_server` stands up an endpoint on the agent whose headers are
exactly what the test says they are, as a bitmask of defects:
`TAPI_HTTP_DEFECT_NO_SECURITY_HEADERS`, `_VERSION_BANNER`,
`_LOOSE_COOKIE`, `_OPEN_CORS`, `_TRACE`, `_WRITE_METHODS`,
`_DUPLICATE_CSP`.

Two uses, and both matter. **Testing the checks**: a check that reports
nothing looks the same whether the endpoint is clean or the check is
broken, and pointing it at a server that is wrong in a known way is the
only way to tell. **Testing a client**: when the device under test is
the HTTP client, this is how to find out whether it minds being told
something it should mind.

It is a `python3` script written to the agent and run there — python3
rather than a real web server because every agent already has it, and
what is wanted is control over individual headers rather than a
service. `tapi_http_server_start()` does not return until the socket is
bound; it waits for a line the script prints after the bind, because
starting a server and carrying on is a race that passes on a quiet
machine and fails in CI.

## Scope

- **It asks the endpoints the suite's own configuration names**, one
  request at a time, with the method the caller chose. No path
  guessing, no payloads meant to break anything, no credentials it
  invented.
- **It reads what a service says about itself.** Finding a way in is
  not what this is for.
- **`insecure` is off by default.** A test that turns it on to make a
  request work has found a defect and hidden it; report it with
  [tsf-tls](https://github.com/interpretica-io/tsf-tls) instead.
