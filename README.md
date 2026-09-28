# dns-shield

**Your ISP probably isn't blocking that site — it's lying to your resolver.**

`dns-shield` diagnoses ISP DNS poisoning and, when the diagnosis is positive,
works around it by resolving over DNS-over-HTTPS and connecting to the real
address with SNI and `Host` preserved.

MIT licensed. No runtime dependencies.

---

## The symptom

You try to reach a service. It fails instantly. Every time. You search around,
find other people in your country saying the same thing, and conclude:

> "X is geo-blocked here" or "X is banned in my country".

**That conclusion is often wrong.**

### The measured example

This is real output from the machine this library was written on, in Jakarta,
on an Indonesian ISP (Biznet):

```
$ dig +short fapi.binance.com
202.169.44.80
```

Every `*.binance.com` hostname resolved to that **one** address. Connecting to it:

```
$ python -m dns_shield.cli check fapi.binance.com --path /fapi/v1/ping
system DNS : 202.169.44.80
DoH (cloudflare) : 108.138.141.35, 108.138.141.52, 108.138.141.24, 108.138.141.5
             CNAME -> d2ukl3c6tymv7q.cloudfront.net

probe sys  : connection refused (RST) in 23 ms ([Errno 61] Connection refused)
probe doh  : HTTP 200 in 183 ms, cert=*.binance.com

VERDICT: POISONED
```

(The `probe sys` line reads `timed out (no response)` on runs where the address
drops instead of refusing. Both are the same finding — see the note below.)

The service was **never blocked**. The real hosts sit behind CloudFront, are
fully reachable from that same connection, and answer `HTTP 200`. The only
thing broken was name resolution — a local lie. A `--resolve` request to the
real address succeeded in 150 ms:

```
$ curl -s --resolve fapi.binance.com:443:108.138.141.52 \
       https://fapi.binance.com/fapi/v1/ping
{}
```

The user (me) had concluded "Binance is blocked in Indonesia" and given up. That
was false.

This is a **general class of failure**. Any ISP that poisons any domain produces
the same false conclusion. The domain is incidental; the pattern is not.

---

## The diagnosis: poisoning vs. a real block

These look similar from a browser and are completely different underneath.
Here is how to tell them apart.

| Probe | DNS poisoning | Genuine block / outage |
|---|---|---|
| System DNS answer | A **single shared address** for many unrelated hosts | Normal, varied addresses |
| That address, dialled | **Active refusal (RST)** *or* **blackhole timeout** — nothing to read either way | — |
| Independent DoH (Cloudflare, Google, Quad9) | **Disagrees**, typically a CDN CNAME like `*.cloudfront.net` | Agrees with the system resolver |
| The DoH address, dialled with SNI | **Works** — HTTP 200 | Fails too |
| TLS certificate on the DoH address | Valid for the hostname you asked for | — |
| HTTP status | 2xx | 451, 403, or a real 5xx |

### The fingerprint

1. **The address actively refuses, or silently drops.** Both modes are seen, and
   both indicate poisoning:

   - **Active refusal (instant RST).** A reset arrives in ~10 ms from an address
     that is not on the same continent. Real servers do not do this.
   - **Blackhole timeout.** Nothing comes back at all.

   These are *different* failure modes with different causes — and they are worth
   distinguishing, because the remedies differ. A refusal is immediate to detect;
   a blackhole needs a longer deadline and may indicate a firewall rather than a
   DNS appliance. `dns-shield` records the measured latency and the failure kind
   separately and reports both.
2. **A bogus shared IP.** `whois 202.169.44.80` → Biznet, Jakarta, a residential
   range that "serves nothing". One address answering for an entire domain is
   not how infrastructure is built; it is how a blackhole appliance is built.
3. **DoH gives the truth.** Cloudflare, Google and Quad9 agree on a different
   answer, and it is a CDN.
4. **The real address works.** Dial it with SNI preserved and you get HTTP 200.

### What is NOT poisoning

Getting this wrong is worse than useless, so `dns-shield` is deliberately
willing to say "unreachable" or "I don't know":

- **The host is genuinely down.** If the real address also fails, that is an
  outage. `dns-shield` reports `UNREACHABLE`. It does not blame your ISP.
- **A genuine geo-block returning HTTP 451.** A 451 means a real server
  received your request and refused it by policy. That is a *real* restriction.
  Reported as `UNREACHABLE`, never as poisoning.
- **HTTP 403 on a route that does not exist.** An API host commonly returns 403
  for `/` while serving 200 on its real routes. That is a statement about the
  path, not about reachability.
- **TLS interception by a corporate proxy.** TCP connects, TLS fails. Different
  problem, reported differently.
- **Two resolvers disagreeing but both working.** That is CDN rotation, not a
  lie. Reported as `HEALTHY`.

> **A note on non-determinism — measured, and important.** The original report
> described an instant RST in ~10 ms. Re-measuring the same address on the same
> machine later gave a *mixture*. Ten consecutive TCP connects to
> `202.169.44.80:443` produced:
>
> ```
> trial 0: ConnectionRefusedError  errno=61  in 2012.2 ms
> trial 1: TimeoutError                      in 5001.5 ms
> trial 2: ConnectionRefusedError  errno=61  in 2018.5 ms
> trial 3: ConnectionRefusedError  errno=61  in 3027.5 ms
> trial 4: ConnectionRefusedError  errno=61  in    9.4 ms
> trial 5: TimeoutError                      in 5001.4 ms
> trial 6: TimeoutError                      in 5001.2 ms
> trial 7: TimeoutError                      in 5001.4 ms
> trial 8: ConnectionRefusedError  errno=61  in   18.8 ms
> trial 9: TimeoutError                      in 5001.5 ms
> ```
>
> `curl` sees the same split on the same address — `exit=7` (refused) at 13 ms,
> 1015 ms, 12 ms and 4015 ms, and `exit=28` (timeout) at 8 s.
>
> So **both signatures are real, and the mode varies run to run.** A blackhole
> that rate-limits its own resets behaves exactly like this. The consequences
> for the tool:
>
> - A fast refusal is treated as strong evidence, and reported as such.
> - A slow refusal is still an active refusal — the connection was rejected, not
>   dropped — and is labelled `refused-slow`.
> - A timeout is **not** treated as evidence against poisoning.
> - The verdict never hinges on which mode occurred; the latency and the mode
>   are recorded as evidence, so you can see it for yourself.

---

## Install

```bash
pip install dns-shield
```

Optional, only if you want the `requests` adapter:

```bash
pip install "dns-shield[requests]"
```

Then:

```bash
dns-shield check fapi.binance.com
```

That is the whole quick start. If it prints `POISONED`, you have a diagnosis and
a workaround. If it prints anything else, you do not, and the tool will tell you
why rather than inventing a verdict.

---

## Usage

### Command line

**`check` — diagnose a hostname.**

```bash
dns-shield check fapi.binance.com
```

Exit codes are stable and meant for scripts:

| Code | Meaning |
|---|---|
| `0` | `HEALTHY` — resolvers agree and the host responds |
| `1` | `POISONED` (resolver is lying) or `SUSPICIOUS` (inconclusive — investigate) |
| `2` | `UNREACHABLE` or `UNKNOWN` — genuinely down, or not enough evidence |
| `3` | Bad usage |

Both `1` and `2` are non-zero, so a naive `dns-shield check host || alert` treats
"inconclusive" the same as "poisoned". Gate on the JSON verdict if you need to
distinguish them: `dns-shield check host --json | jq -e '.verdict == "poisoned"'`.

```bash
# Use a specific DoH provider, or several with failover
dns-shield check example.com --provider cloudflare --provider google

# Probe a route the host actually serves (important for API hosts)
dns-shield check fapi.binance.com --path /fapi/v1/ping

# Show the shared-bogus-IP pattern: corroborating evidence, not the verdict
dns-shield check fapi.binance.com --sibling api.binance.com --sibling www.binance.com

# Machine-readable
dns-shield check fapi.binance.com --json
```

Use it in CI:

```bash
dns-shield check api.example.com --json || echo "DNS problem detected"
```

**`fetch` — GET a URL through the shield.**

```bash
dns-shield fetch https://fapi.binance.com/fapi/v1/ping
```

```
HTTP 200 via 108.138.141.52
url: https://fapi.binance.com/fapi/v1/ping
--------------------------------------------------------------------
{}
```

Resolves the host over DoH, connects to that address, keeps SNI and `Host` set
to the hostname. One request; no global changes.

**`hosts` — print the real addresses.**

```bash
dns-shield hosts fapi.binance.com
```

With `--hosts-file` it emits an `/etc/hosts` fragment. **That is the fragile
option**, and the command says so in its own output. See
[Why not `/etc/hosts`](#why-not-etchosts).

### Library

```python
from dns_shield import diagnose, resolve_and_call

# Diagnose
result = diagnose("fapi.binance.com", path="/fapi/v1/ping")
print(result.verdict)          # Verdict.POISONED
print(result.summary)
print(result.exit_code)        # 1
for reason in result.reasons:
    print(" -", reason)

# One-line workaround
response = resolve_and_call("https://fapi.binance.com/fapi/v1/ping")
print(response.status, response.address, response.text[:80])
```

Structured output for tooling:

```python
import json
print(json.dumps(result.to_dict(), indent=2))
```

Choosing providers, and failing over between them:

```python
from dns_shield import DohResolver, SniHTTPClient

resolver = DohResolver(["cloudflare", "google", "quad9"])
records = resolver.query_records("example.com", "A")
print(records.addresses)   # ('104.20.23.154', '172.66.147.243')
print(records.cnames)      # the CNAME chain, if any
print(records.provider)    # which provider actually answered

client = SniHTTPClient(resolver=resolver)
print(client.get("https://example.com/").status)
```

Adding your own provider:

```python
from dns_shield import DohProvider, DohResolver

mine = DohProvider("mine", "https://dns.mycompany.internal/dns-query")
resolver = DohResolver(mine)          # any `application/dns-json` endpoint
```

Body-level error codes (an API that returns HTTP 200 with an error inside):

```python
from dns_shield import SniHTTPClient, BINANCE_SUCCESS_CONTRACT

client = SniHTTPClient()
# A verified trap: this returns HTTP 200 with {"code": "11012030"}.
try:
    client.get_json(url, contract=BINANCE_SUCCESS_CONTRACT)
except Exception as exc:
    print("body-level failure:", exc)

# Or define your own contract
from dns_shield import SuccessContract
client.get_json(url, contract=SuccessContract(field="status", value="ok"))
```

---

## How it works

Three steps, and the second one is the part most people get wrong.

### 1. Resolve over DoH

Query Cloudflare, Google or Quad9 over HTTPS (`application/dns-json`). The ISP
cannot forge these answers without breaking TLS to a major provider, in which
case you have a much bigger problem and `dns-shield` will say so.

Answers carry a TTL and are cached, re-queried on expiry, and invalidated when
an address fails.

### 2. Dial the address — and this is the catch

**You cannot resolve over DoH and then hand the URL to `requests`.** `requests`,
`urllib` and `http.client` all call `socket.create_connection` internally, which
**re-resolves the hostname through the poisoned system resolver** and throws
away the address you carefully looked up. The request then fails exactly as if
you had done nothing.

This is measured, not theoretical. On the affected machine:

```
requests.get("https://fapi.binance.com/fapi/v1/ping")  ->  ConnectTimeout (5.0 s)
socket -> DoH IP, server_hostname="fapi.binance.com"   ->  HTTP/1.1 200 OK (195 ms)
```

So `dns-shield` speaks HTTP/1.1 itself, over a socket it opened to a specific
address. **The transport never calls `socket.getaddrinfo` on the request path.**
(The *diagnostic* module does call it — deliberately, to observe what the
suspect resolver returns. That is the thing being measured, not a leak.) The test suite
proves this: `socket.getaddrinfo`, `socket.socket` and
`socket.create_connection` are all patched to raise, and the request still
succeeds against a mocked socket.

If you prefer a library, `urllib3.HTTPSConnectionPool` with an explicit
`server_hostname` would also work — but it is a heavier dependency for the same
result, so this project uses the stdlib.

### 3. Preserve SNI

TLS SNI is set to the **hostname**, not the address:

```python
context.wrap_socket(sock, server_hostname="fapi.binance.com")
```

This is not a nicety. CloudFront routes on SNI, so:

```bash
$ curl https://108.138.141.52/                     # bare IP
curl: (35) error:...:tlsv1 alert internal error

$ curl --resolve fapi.binance.com:443:108.138.141.52 https://fapi.binance.com/
{}                                                  # 200
```

A bare-IP request fails because there is no SNI to route on. This is also why
`/etc/hosts` is a poor fit, and why TLS verification keeps working: the server
presents a valid certificate for the real hostname.

**Certificate verification is enforced, not bypassed.** The transport uses
`ssl.create_default_context()`, which sets `verify_mode = CERT_REQUIRED` and
`check_hostname = True` against the system trust store. Dialling a real address
while claiming a different hostname raises `SSLCertVerificationError` and is
reported as a `tls` failure — it is not silently accepted. This is checkable and
tested: `tests/test_import_safety.py::TestCertificateVerification`. There is no
`verify=False` anywhere in this codebase, and
`tests/test_patch.py::TestTlsVerificationIsNeverDisabled` fails the build if one
is ever added.

The certificate is also *evidence*: in the measured case the observed
`cert=*.binance.com` on the DoH address is what proves that address really
serves the host, and it is printed as a reason in the verdict.

### Why not `/etc/hosts`

Because it is fragile, and because it is a *global* change with a *local*
problem:

- It needs `sudo`, so it cannot live inside a library or a test suite.
- **The addresses rotate.** One host was observed rotating across `.5`, `.24`,
  `.35` and `.52` of a CloudFront `/24` within minutes. A stale entry does not
  fail loudly — it fails *intermittently*, which is far worse to debug.
- It affects every process on the machine, including ones you did not intend.
- It is easy to forget, and hard to notice when it goes stale.

`dns-shield hosts --hosts-file` will still emit a fragment if you want one, and
prints the warning and the undo command alongside it.

### Why IPs are never hardcoded

For the reason above. Every address is re-resolved per run, with retry across
the answer set: if the first address fails, the next one is tried before giving
up. Once every known address has failed, the answer set is presumed stale and
re-queried.

---

## Limitations and honest caveats

**Read this section before trusting the tool.**

- **It does not defeat a genuine network-level block.** If your ISP blackholes
  the real IP ranges, or blocks at L3/L4, or does deep packet inspection on the
  TLS handshake, DNS-over-HTTPS will not help you. `dns-shield` will report
  `UNREACHABLE` and that is the correct answer. There is no workaround here —
  that is not a bug.
- **It only fixes name resolution.** It does not tunnel, encrypt, or obfuscate
  your traffic. Your ISP can still see which addresses you connect to.
- **TLS interception is a different problem.** If an employer's proxy is
  MITM-ing your traffic, TCP will connect and TLS will fail. That is reported
  as `UNREACHABLE`, not poisoning. `dns-shield` will never disable certificate
  verification to get around this — the whole technique *depends* on SNI and
  valid certificates, and silently accepting a bad certificate would be a
  security downgrade disguised as a fix.
- **HTTP/1.1 only.** No HTTP/3 or QUIC. No connection pooling, no keep-alive
  reuse (`Connection: close` per request).
- **Redirects are not followed.** A 3xx is returned to you verbatim. Following a
  redirect would mean resolving a second host, and the entire point is to
  control resolution. Follow it yourself with an explicit second call.
- **No proxy support.** No `HTTP_PROXY` or `CONNECT` tunnelling.
- **IPv4 dialling only.** AAAA records can be resolved, but the transport dials
  IPv4.
- **The 403 trap.** API hosts often return 403 for `/` while serving 200 on
  their real routes. Always pass `--path` pointing at a route the host actually
  serves, or you may get `UNREACHABLE` for a host that is fine.
- **The classifier is a heuristic.** It is built on measured evidence and it is
  willing to say "unknown", but it is not a formal proof. Read the evidence
  lines it prints — they are there so you can disagree with the verdict.
- **`SUSPICIOUS` means the tool does not know.** When the resolvers disagree but
  the DoH answer did not work either, there is no defensible verdict. Treat
  exit code 1 with `SUSPICIOUS` as "investigate", not "confirmed".

### Legal and ethical note

`dns-shield` diagnoses and works around **DNS misconfiguration and
misresolution**. That is what it does and all it does — it corrects a false
answer, which is a network-correctness problem, not a circumvention technique.

**You are responsible for complying with the rules of your own jurisdiction.**
This project does not exist to evade lawful restrictions, and it will not help
you do so: see the limitations above — it does not defeat a genuine
network-level block and makes no attempt to hide your traffic. If a court order
or a law requires a service to be unavailable to you, a working DNS lookup is
not a loophole, and this tool does not pretend otherwise.

Consider, before using this, whether the restriction you are working around is
one you should be working around. Diagnosing a misconfiguration is reasonable.
Deliberately circumventing a legal restriction is a decision you make, not one
this library makes for you.

---

## Dependencies

**Runtime: none.** Everything uses the standard library.

| | Why |
|---|---|
| `urllib.request` | DoH queries over HTTPS. In the stdlib. |
| `socket`, `ssl` | The SNI-preserving dial. Must be the stdlib — see step 2 above. |
| `argparse`, `json` | CLI. |

| Optional extra | Why |
|---|---|
| `requests>=2.28` | Only for `RequestsShieldAdapter`. Not needed for the CLI or the main API. |

| Dev | Why |
|---|---|
| `pytest`, `pytest-cov` | The test suite. |

`requests` is imported lazily, so `import dns_shield` does not pull in
`requests`, `urllib3` or `certifi`.

---

## Testing

```bash
pip install -e ".[dev]"
python -m pytest -q
```

The suite is **offline by default**. An autouse fixture replaces
`socket.socket`, `socket.create_connection` and `socket.getaddrinfo` with
functions that raise, so a new test cannot accidentally acquire a network
dependency. A library about network failure whose own tests need the network is
a library nobody can trust in CI.

Opt-in live tests are marked and deselected by default:

```bash
python -m pytest -m live -q
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

MIT — see [LICENSE](LICENSE). Chosen deliberately, so this can be used,
modified and redistributed freely, including by people who just want the
diagnosis without the workaround.
