# security-log-scan

[![CI](https://github.com/Surtov/security-log-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/Surtov/security-log-scan/actions/workflows/ci.yml)

A command-line tool that analyzes web access logs and Linux auth logs for
security incidents using configurable detection rules, and correlates
findings across log sources.

Runs as a one-shot scan, or as a live monitor that alerts as attacks unfold
(`--follow`).

> **AI collaboration:** this tool was built with Claude Code using a
> plan → build → adversarially-review → fix loop. The full conversation history,
> and an honest account of the bugs those reviews found in my own code, is in
> **[AI-COLLABORATION.md](AI-COLLABORATION.md)**.

## Quick start

Requires Python 3.10+.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"

security-log-scan sample-logs/webserver.log sample-logs/auth.log
```

JSON output for pipelines:

```bash
security-log-scan sample-logs/webserver.log sample-logs/auth.log --format json
```

Run the test suite:

```bash
pytest                 # 135 tests
pytest -p randomly     # random order - proves no inter-test dependencies
```

CI (`.github/workflows/ci.yml`) runs the suite on Linux and Windows across
Python 3.10 and 3.12 in randomized order, and includes a job that *exercises*
the exit-code gate (clean log → 0, incidents → build fails, bad config → 2)
rather than just claiming it works.

## CLI

```
security-log-scan FILE [FILE ...] [options]

  --rules PATH          YAML file overriding built-in rule thresholds/lists
  --format text|json    Report format (default: text)
  --output PATH         Write the report to a file instead of stdout
  --min-severity LEVEL  low|medium|high|critical - report floor, also drives
                        the exit code (default: low)
  --log-year YEAR       Year for syslog timestamps (auth.log carries none);
                        defaults to the year observed in a co-processed web log
  -f, --follow          Live mode: tail the files and alert as detections fire
                        (Ctrl-C to stop). Survives log rotation.
  --poll-seconds N      How often --follow checks for new lines (default: 1.0)
```

`--follow` streams alerts to stdout, so it is not combined with `--output` or
`--format json` (a batch report format has no meaning for a stream that never
ends); the combination is rejected rather than half-supported.

Exit codes: `0` no incidents at/above the floor, `1` incidents found
(CI-gateable), `2` usage, config, input-format, **or report-write** error.
Individual malformed log lines never affect the exit code — they are reported
in the Data Quality section.

The exit-code contract matters more than it looks: an uncaught crash would also
exit `1`, making it indistinguishable from "incidents found" in CI. The tool
therefore treats untrusted log content and unwritable output paths as handled
conditions rather than letting them raise — see Robustness below.

## What it detects

| Rule | Signal | Severity |
|---|---|---|
| `brute_force_web` | Repeated failed web logins; escalates if a success follows | MEDIUM / CRITICAL |
| `brute_force_ssh` | Repeated failed SSH logins; escalates on success; also flags username enumeration | MEDIUM / CRITICAL |
| `sensitive_path_scan` | Bursts of requests to admin panels / sensitive files (`/admin`, `/.env`, ...) | MEDIUM |
| `path_traversal` | `../` sequences (including URL-encoded) in request paths | HIGH |
| `sql_injection` | SQL payloads in query strings (`UNION SELECT`, stacked `DROP TABLE`, ...) | HIGH |
| `rate_limit_abuse` | Write-request bursts to one endpoint; higher severity if the server never returned 429 | MEDIUM / HIGH |
| `privilege_escalation` | sudo-as-root commands touching a watch list (`/etc/shadow`, ...) | HIGH |

**Cross-log correlation:** when the same IP is active in more than one log
source within the correlation window, its findings are grouped into a single
incident and the severity is escalated one level. In the sample data,
`10.0.0.50` (web + SSH brute force) and `203.0.113.5` (admin scanning + SSH
username enumeration) both correlate.

**False-positive discipline:** legitimate traffic that superficially resembles
attacks must not fire — `?q=O'Brien` (apostrophe, not SQLi),
`?q=union+station+select+hotels` (keywords, not adjacency), and a benign
`sudo systemctl restart nginx` (watch list, not "any sudo = alert") are all
covered by explicit negative tests.

## Configuring rules

All thresholds, windows, and watch lists live in [rules.yaml](rules.yaml)
(which mirrors the built-in defaults — the tool runs without it). Override any
subset; unknown sections or keys are rejected to catch typos:

```yaml
brute_force_web:
  threshold: 6
sql_injection:
  enabled: false
```

Two config notes worth knowing:

- **What counts as a successful login** is configurable (`success_statuses`,
  `success_methods`). The default is a `POST` returning `200` or `302` — a
  `GET /login → 200` is the form re-rendering, not a credential submission, and
  treating it as success produces a false CRITICAL "account compromise".
- `fail_statuses` and `success_statuses` **may not overlap** (rejected at load
  time). If your application returns `302` on *failed* logins too, remove `302`
  from `success_statuses`.

## Design

```
files -> per-format parser (streaming, line-by-line)
      -> normalized LogEvent stream
      -> detection rules (windowed, config-driven, push-based process/finalize)
      -> cross-log correlator (per-actor grouping + escalation)
      -> text / JSON reporter -> exit code
```

- **Streaming & bounded memory:** files are read line-by-line; windowed rules
  keep per-actor state in time-evicted deques and capped sets, and release state
  for actors that turn out to be innocent. Memory is measured, not assumed — see
  [Memory and throughput](#memory-and-throughput).
- **Format detection** samples the first lines of each file and picks the
  parser that matches most, so a file that *starts* with a malformed entry is
  still recognized.
- **Malformed lines** (e.g. the `[MALFORMED ENTRY` line in the sample) are
  counted, capped, reported under Data Quality, and never stop the scan.
- The web parser deliberately tolerates spaces and quotes inside the request
  path — attack payloads like `GET /search?q=' UNION SELECT ... HTTP/1.1` are
  exactly the lines the SQLi rule must see, so a stricter regex would silently
  drop them as malformed.

## Detection is data-driven, not sample-driven

No IP address, hostname, or username appears anywhere in `src/` or `rules.yaml`.
Rules key their state on whatever actor the parser extracts, so any IPv4 or IPv6
address is handled identically — the sample logs are test fixtures, not
detection inputs. What `rules.yaml` configures is *behavior* (thresholds, time
windows, sensitive paths, watch-listed sudo commands), never identities.

The tool has no allow-list or block-list of actors: an attacker is anyone whose
*behavior* trips a rule.

## Memory and throughput

Measured, not asserted:

| lines | file size | peak memory | scan time | throughput |
|---|---|---|---|---|
| 100,000 | 8.3 MB | 0.2 MB | 2.7 s | ~36,000 lines/sec |
| 1,000,000 | 83.1 MB | **0.2 MB** | 31.2 s | ~32,000 lines/sec |

Timings are from a clean run; peak memory is from a separate run under
`tracemalloc`. Keeping them separate matters — the profiler instruments every
allocation and slows the scan by about **5×**, so timing a profiled run measures
the profiler, not the tool. (An earlier version of this table did exactly that
and under-reported throughput sixfold.)

**Memory is flat in the size of the log.** What it *does* scale with is the
number of distinct **suspects** — actors currently showing a suspicious signal.
Innocent actors are released once their time window expires, so a log with a
million distinct benign IPs costs nothing to scan.

That claim used to be false, and running the benchmark is what caught it. The
rules allocated per-actor state the moment an IP touched a rule's trigger
surface — *including a perfectly ordinary successful login* — and never released
it, so peak memory grew linearly and hit **198 MB at 1M lines**. The fix was to
allocate late (a success is not the start of a brute force) and to prune actors
whose window expired with nothing to show. `tests/unit/test_memory_bounds.py`
pins the behavior; a suspect is never pruned, so no detection can be lost.

Throughput is single-threaded and parser-bound (the regexes are the hot path).
~32k lines/sec comfortably covers batch scans and `--follow` on a normal server;
a genuinely high-volume deployment would shard the work per file.

## Real-time monitoring (`--follow`)

Point it at live logs and it alerts as attacks unfold:

```bash
security-log-scan /var/log/nginx/access.log /var/log/auth.log --follow
```

```
[MEDIUM]   10.0.0.50 brute_force_web: 4 failed login attempts within 60s (no success observed)
[CRITICAL] 10.0.0.50 brute_force_web: 4 failed login attempts followed by a successful login
                     - likely account compromise  [correlated: auth+web]
[HIGH]     203.0.113.9 sql_injection: 1 SQL injection payload(s), e.g. 'q=1 UNION SELECT * FROM users--'
```

The same detection rules serve both modes — the tail source simply replaces the
file reader. Three things make it usable rather than merely working:

- **Alerts de-duplicate.** Rules re-derive findings from accumulated state on
  every flush, so a naive loop would re-alert an ongoing attack on every poll.
  An alert re-fires only when the situation genuinely *worsens*: severity
  escalates, or the attack continues. The `MEDIUM → CRITICAL` pair above is that
  working — the attacker's eventual success breaks through the de-duplication.
- **Log rotation is survived.** If the file is truncated or replaced, the tail
  notices it shrank and re-reads from the top instead of going silent.
- **Partial writes are handled.** A line caught mid-write is not parsed until its
  newline arrives.

Memory does not grow with uptime: state is retained only for actors that are
actually suspicious (see below), so a long-running monitor does not accumulate
every user who ever logged in.

## Processing model

Batch and live share one streaming pipeline: files are read line-by-line with
generators, rules are push-based (`process()` per event, `finalize()` to flush),
and windowed state lives in time-evicted deques with capped evidence. Nothing
loads a whole log into memory.

## Robustness: log content is attacker-controlled

Everything the tool reports on is written by the attacker it is reporting on, so
untrusted content must not be able to break the report that describes it:

- **Console markup is neutralized.** Log-derived strings (evidence lines,
  finding messages, actors, file paths) are rendered as `rich.text.Text`, never
  parsed as markup. Otherwise a request path containing `[/nonsense]` crashes
  the run with a `MarkupError` — letting an attacker suppress their own incident
  report — and `[bold red]` silently restyles the output.
- **Report-write failures are handled**, not raised: `--output` to an unwritable
  path prints `error: cannot write report to …` and exits `2`, instead of dumping
  a traceback and exiting `1`.

Both behaviors are covered by regression tests in
`tests/integration/test_cli_end_to_end.py`.

## Known limitations (deliberate)

- **Single URL-decode pass.** A double-encoded payload (`%252e%252e%252f`) is
  not flagged. This matches what the web server itself resolves; decoding
  repeatedly would manufacture false positives on payloads that never traverse
  anything. Pinned by a documenting test so a future change is a conscious one.
- **Detection is per-IP.** Distributed brute force (many IPs, one account) and
  password spraying across valid accounts are not detected.
- **Actor namespaces are disjoint** (`ip` vs `user:name`), so an SSH login
  compromise does not correlate with the subsequent sudo activity of the account
  it compromised.
- Memory scales with the number of concurrent **suspects**. Benign actors are
  released, but a distributed attack from a very large number of distinct
  hostile IPs would still grow state; a hard cap with LRU eviction would be the
  next step.

## Assumptions (explicit)

- **auth.log year:** syslog timestamps carry no year. It defaults to the year
  observed in a co-processed web access log (falling back to the current
  year), and can be pinned with `--log-year`. A wrong year silently disables
  cross-log correlation — there is a test documenting exactly that failure
  mode.
- **auth.log timezone:** assumed UTC, keeping it comparable with the web log's
  `+0000` offsets.
- **Within-file ordering:** log lines are assumed chronologically ordered per
  file (standard for appended logs); no cross-file event reordering is done.
- "Configurable rules" is interpreted as YAML-tunable thresholds/lists, not a
  rule DSL or plugin system.

## Reports contain personal data

Reports quote raw log lines as evidence, so they inherit whatever the source
logs contain — IP addresses and usernames are personal data under GDPR (Art. 4,
Recital 30). Two deliberate choices keep this proportionate:

- Evidence is capped at 5 lines per finding, and only for lines that actually
  triggered a detection (the security-analysis purpose that Recital 49 covers).
- Malformed lines carry no such justification and are exactly where stray
  secrets and PII end up, so the report gives an **honest count** plus a bounded
  5-line sample rather than reproducing all of them.

Generated reports inherit the retention obligations of the logs they summarize —
the legitimate-interest basis covers analyzing the data, not storing the output
indefinitely.

## Future work (deliberately not built)

- **Other ingestion sources.** `--follow` tails files today; a syslog or Kafka
  source would slot into the same pipeline without touching a detection rule.
- A `--redact` mode (IP truncation / username hashing in evidence lines) for
  reports shared beyond the incident-response boundary.
- Additional detections (XSS payloads, SSRF-indicative URLs, 404-ratio and
  scanner-User-Agent recon, distributed brute force, geo/ASN enrichment) slot in
  as new `Rule` subclasses.
- A hard cap (LRU) on tracked suspects, to bound memory even under a
  large-scale distributed attack.
- Parser throughput: the regexes are the hot path (~32k lines/sec, single
  threaded). Sharding per file would be the cheapest win.
