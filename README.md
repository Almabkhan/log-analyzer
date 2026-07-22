# Log Analyzer

A real log analysis tool that parses SSH authentication logs and web server
access logs, then applies threshold-based detection to flag genuine
security-relevant patterns — brute-force attacks, directory scanning, and
SQL injection attempts. This is a small-scale version of what SIEM tools
(Splunk, ELK, etc.) do for a living.

## What it actually detects

**SSH logs (`auth.log` format):**

- Brute-force login attempts — an IP with repeated failed password attempts
  above a configurable threshold
- "Possible compromised credential" — a successful login from an IP that
  had just brute-forced the host (a strong signal the attack succeeded)

**Web access logs (Apache/Nginx combined format):**

- Directory/file scanning — an IP generating many 404s while probing for
  hidden paths (`/wp-login.php`, `/.env`, `/.git/config`, etc.)
- Brute-force web login attempts (repeated 401s on `/login`)
- Possible compromised credential (login success after repeated failures)
- Possible SQL injection — request paths containing common injection
  patterns (`UNION SELECT`, `' OR '1'='1`, `; DROP TABLE`), checked against
  the **URL-decoded** path so encoded payloads are still caught

## Installation

```bash
git clone https://github.com/Almabkhan/log-analyzer
cd log-analyzer
```

No external dependencies are required to run the analyzer (standard
library only). `pytest` is only needed for the test suite.

## Usage

**Analyze the included sample SSH log:**

```bash
python log_analyzer.py sample_logs/auth.log --type ssh
```

**Analyze the included sample web access log:**

```bash
python log_analyzer.py sample_logs/access.log --type web
```

**Adjust the detection threshold** (default: 5 failed attempts):

```bash
python log_analyzer.py sample_logs/auth.log --type ssh --threshold 3
```

**Get raw JSON output:**

```bash
python log_analyzer.py sample_logs/auth.log --type ssh --json
```

## Example output

```text
=================================================================
  LOG ANALYSIS REPORT (ssh)
=================================================================
  Lines analyzed : 30
  Alerts found   : 3
-----------------------------------------------------------------

  [CRITICAL] possible_compromised_credential
    ip: 45.155.205.87
    user: root
    note: Successful login from an IP that previously brute-forced this host

  [HIGH] brute_force
    ip: 45.155.205.87
    attempt_count: 10
    usernames_tried: ['root']

  [MEDIUM] brute_force
    ip: 185.220.101.4
    attempt_count: 8
    usernames_tried: ['admin', 'root']

=================================================================
```

## How it works

1. Log lines are matched against **real regex patterns** built for the
   actual SSH auth.log and Apache/Nginx combined log formats — not
   simplified toy formats.
2. Matched events are grouped by source IP using a `defaultdict`.
3. Any IP crossing the failure-count threshold is flagged as brute force;
   severity escalates to `high` at 2x the threshold.
4. If a flagged IP later shows a *successful* login, that's flagged
   separately and more severely (`critical`) — a failed brute force is
   a nuisance, a **successful** one is a breach.
5. For web logs, request paths are URL-decoded before checking for SQL
   injection patterns, since real attackers URL-encode payloads
   (`%20` for spaces, etc.) and a naive string search would miss them.

## Running the tests

```bash
pip install pytest
python -m pytest test_log_analyzer.py -v
```

15 tests cover SSH log parsing, web log parsing, brute-force detection,
compromised-credential detection, directory-scanning detection, and SQL
injection detection — including a check that clean/normal traffic produces
**zero** false-positive alerts.

## Project structure

```text
log-analyzer/
├── log_analyzer.py         # main application
├── test_log_analyzer.py    # unit tests
├── sample_logs/
│   ├── auth.log             # sample SSH log with realistic attack patterns
│   └── access.log           # sample web access log with realistic attack patterns
├── requirements.txt
└── README.md
```

## Limitations / possible extensions

- Only supports the standard `auth.log` and Apache/Nginx combined log
  formats — other formats (Windows Event Log, syslog variants) would need
  their own parser
- Detection is threshold-based, not ML-based — effective for clear
  patterns, but won't catch slow/low-and-slow attacks spread over days
- Could be extended to output alerts to a file, send a webhook/email, or
  ingest logs continuously (tail -f style) instead of one-shot analysis

## Disclaimer

The sample logs in `sample_logs/` are synthetic data created for
demonstration and testing — they do not contain any real user data.
