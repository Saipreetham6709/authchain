# authchain

Authentication log correlation and attack-chain reconstruction engine.

Point it at raw `auth.log`/`secure` files from one or more hosts, and
instead of a flat list of "failed password" lines, you get a small
number of incidents that tell a story:

```
brute force burst  →  credential breakthrough  →  privilege escalation  →  lateral movement
```

Each stage only escalates severity when the *next* signal actually
shows up -- a brute force alone is `medium`, a burst that ends in a
successful login is `high`, and a full chain into `sudo` usage and a
second host is `critical`. The goal is an alert you'd actually trust,
not one you learn to ignore.

Built this as a way to actually implement the correlation logic a SOC
analyst does by hand -- sliding-window burst detection, per-user
login-hour baselining, and multi-stage incident chaining -- rather
than another script that just greps for `Failed password`.

## Why

Most log-analysis toy projects either count failed logins (not
interesting) or wrap an ML library around a CSV without explaining
what the model is doing (not verifiable). This does neither: every
detection is a plain, readable, testable Python function, and the
thresholds that drive them are config, not code. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design
writeup, including the limitations I chose not to hide.

## Quick start

```bash
git clone https://github.com/<you>/authchain.git
cd authchain
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .

# generate a synthetic multi-host attack scenario to try it on
authchain generate-demo

# correlate it into incidents
authchain analyze sample_data/*.log

# open authchain_report.html in a browser
```

Expected output against the bundled demo data:

```
Parsed 107 events across 2 host(s).
Found 2 incident(s): {'critical': 1, 'high': 0, 'medium': 0, 'low': 1}
Reports written to authchain_report.json and authchain_report.html
```

The critical incident is the full chain: a 6-attempt brute force
against `root` on `web01`, a successful login 12 seconds after the
burst, two `sudo` commands (including a `cat /etc/shadow`), and the
same credentials reaching `db01` about seven minutes later. The low
incident is an unrelated 3am login by a different user that's simply
outside their normal hours -- included on purpose, to show the engine
doesn't just fire on everything.

## Usage

```bash
authchain analyze LOGFILE [LOGFILE ...] [OPTIONS]

Options:
  --baseline PATH     Log file(s) to fit the off-hours baseline from.
                       If omitted, the baseline is fit from the
                       analysis window itself (a weaker signal --
                       the tool warns you when this happens).
  --config PATH        YAML file overriding detection thresholds.
                        See thresholds.example.yaml and docs/THRESHOLDS.md.
  --year INT            Year to assume for syslog timestamps (they
                         don't carry one). Defaults to the current year.
  --out-json PATH        Default: authchain_report.json
  --out-html PATH        Default: authchain_report.html
```

Real-world example, pointing at actual bastion host logs with a
two-week-earlier baseline and custom thresholds:

```bash
authchain analyze /var/log/auth.log \
  --baseline /var/log/auth.log.1 \
  --config thresholds.example.yaml \
  --year 2026
```

## How it works

Five detection passes over a time-sorted event stream -- brute force,
breakthrough, privilege escalation, lateral movement, off-hours --
each a plain function, chained together and merged into incidents.
Full writeup with the reasoning behind every threshold and every
"why not X instead" in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

```
auth.log(s) → parser → AuthEvent stream → correlate.py (5 passes) → Incidents → JSON + HTML report
```

## Testing it against a scenario you control

`authchain generate-demo` (backed by `authchain/demo_data.py`) builds
a reproducible synthetic dataset: ~10 days of normal per-user login
baseline, then an attack day with a labeled brute-force → breakthrough
→ privesc → lateral-movement chain, plus deliberate noise (a
sub-threshold failed-login burst that should produce *no* incident).
That labeled scenario is also what `tests/test_correlate.py` asserts
against, so the detection logic and the demo data can't silently drift
apart.

```bash
pip install -r requirements.txt   # includes pytest
pytest tests/ -v
```

## Project layout

```
authchain/
├── authchain/
│   ├── parsers/          # log format parsers (currently: linux syslog auth.log)
│   ├── templates/         # Jinja2 HTML report template
│   ├── models.py           # AuthEvent / Incident data structures
│   ├── baseline.py          # per-user login-hour statistical baseline
│   ├── config.py             # threshold loading (defaults + YAML overrides)
│   ├── correlate.py           # the five detection passes
│   ├── report.py               # JSON + HTML report generation
│   ├── demo_data.py             # synthetic attack scenario generator
│   └── cli.py                    # click-based CLI
├── sample_data/            # generated demo logs (committed as a worked example)
├── tests/                    # pytest suite, asserts against the demo scenario
├── docs/                       # architecture + threshold tuning writeups
└── thresholds.example.yaml
```

## Limitations (read before pointing this at production logs)

- Timestamps in the classic BSD format don't carry a year; the parser
  assumes "now" unless you pass `--year`. A log spanning Dec 31 →
  Jan 1 will misparse. See `docs/ARCHITECTURE.md`.
- Two syslog header formats are supported (classic BSD and rsyslog's
  ISO 8601 default), auto-detected per file. Timezone offsets in the
  ISO format are dropped (treated as naive local time) so timestamps
  stay comparable against the BSD format, which has none. A
  multi-timezone log aggregation setup would need that revisited.
  journald JSON or a Windows Security-Event export would be the
  natural next formats to add -- same "new header regex, shared body
  parsing" pattern.
- The off-hours baseline treats hour-of-day linearly, so it
  under-flags users whose normal hours straddle midnight. Documented
  in `baseline.py`, not silently wrong.
- Stateless by design -- point it at the window you care about each
  run. No de-duplication across repeated runs on overlapping log
  ranges yet.

## License

MIT, see [LICENSE](LICENSE).
