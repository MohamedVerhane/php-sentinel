# PHP Sentinel

A small, no-nonsense security scanner for PHP code.

It reads your source files, figures out which values come straight from the user
(`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER`, `$_FILES`), and tells
you where those values end up in something dangerous — a SQL query, HTML output,
a shell command, an include, or a file upload. All without ever running your
code.

## Why this exists

We all write a slightly sloppy query or echo a bit of user input without
escaping it at some point. It's easy to miss. PHP Sentinel is meant to catch
that kind of thing before anyone ships it — the sort of bug that's trivial to
fix when you see it lined up in front of you with a file and line number, and a
pain to track down months later.

I built it to be honest about what it can and can't do. Static analysis can't
prove your code is safe; it just points at places worth a second look. So
treat the output as a checklist, not a verdict.

## What it checks

| ID     | Rule                 | Severity | CWE    |
|--------|----------------------|----------|--------|
| SEC001 | SQL Injection        | High     | CWE-89 |
| SEC002 | Cross-Site Scripting | Medium   | CWE-79 |
| SEC003 | Command Injection    | High     | CWE-78 |
| SEC004 | File Inclusion       | High     | CWE-98 |
| SEC005 | Unsafe File Upload   | Medium   | CWE-434 |

Each rule has a write-up with remediation advice in [docs/rules.md](docs/rules.md).

## A couple of things I care about

- It never runs your code. It parses the source into an AST and reasons
  about it statically. No includes, no requires, no execution of anything you
  scan.
- It doesn't just grep. It tracks taint — where untrusted values flow —
  through assignments, string concatenation, interpolation, and function call
  arguments. It also knows about common sanitizers, so `htmlspecialchars()`
  doesn't get flagged as an XSS leak.
- It's quiet unless there's something to say. If a scan is clean, it tells
  you so and exits `0`. When it finds something, you get a readable report and
  a `1`. Bad arguments or config get you a `2`.

## Requirements

- PHP 8.2 or newer
- the `json` extension (normally enabled by default)

## Installation

```bash
composer require --dev php-sentinel/php-sentinel
```

Or if you want to run it from a checkout:

```bash
git clone https://github.com/php-sentinel/php-sentinel.git
cd php-sentinel
composer install
vendor/bin/sentinel --version
```

## Using it

Point it at your project. That's basically it.

```bash
# scan the current directory (skips vendor/, node_modules/, .git, etc. by default)
vendor/bin/sentinel scan .

# a couple of specific paths
vendor/bin/sentinel scan app/ resources/views/

# only report HIGH and above
vendor/bin/sentinel scan . --severity=high

# machine-readable output for CI
vendor/bin/sentinel scan . --format=json

# tell it to leave certain things alone
vendor/bin/sentinel scan . --ignore=config --no-progress
```

A clean scan looks like this:

```text
PHP Sentinel
────────────────────────────────────────

Scanning: .

Files scanned: 8
Files skipped: 0
Duration: 0.06s

No findings.

────────────────────────────────────────
0 findings — no security issues detected.
```

And when it finds something, you get the file, the line, and the snippet:

```text
HIGH     SEC001 SQL Injection
src/UserRepository.php:41
User-controlled input ($_GET) reaches a SQL query. Use a prepared statement with bound parameters.
  > $pdo->query($query);
```

Exit codes in plain English:

| Code | Meaning                          |
|------|----------------------------------|
| `0`  | Scan ran, nothing was found      |
| `1`  | Scan ran, it found something     |
| `2`  | Something was wrong with the arguments or config |

## Configuration

For most projects the defaults are fine. When you need to tweak things, copy the
sample file and pass it by name:

```bash
cp config/rules.php .php-sentinel.php
vendor/bin/sentinel scan . --config=.php-sentinel.php
```

You can set which file extensions to scan, which paths to ignore, which rules to
switch on or off, a minimum severity, and the output format. The options are
documented inline in `config/rules.php`.

## JSON output

If you're hooking this into a pipeline, use `--format=json`. The whole output is
one valid JSON document with a summary and the list of findings:

```jsonc
{
    "version": "1.0.0",
    "files_scanned": 120,
    "files_skipped": 3,
    "duration": 0.45,
    "paths": ["src", "tests"],
    "errors": {},
    "findings": [
        {
            "rule_id": "SEC001",
            "rule_name": "SQL Injection",
            "severity": "HIGH",
            "title": "Potential SQL Injection",
            "message": "User-controlled input ($_GET) reaches a SQL query.",
            "cwe": "CWE-89",
            "file": "src/UserRepository.php",
            "line": 41,
            "column": 9,
            "code": "$pdo->query($query);"
        }
    ],
    "summary": { "info": 0, "low": 0, "medium": 1, "high": 4, "critical": 0 }
}
```

## Using it in CI

Throwing it into GitHub Actions is a few lines — the exit code does the work for
you:

```yaml
security-scan:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: shivammathur/setup-php@v2
      with:
        php-version: '8.3'
    - run: composer install --no-interaction --prefer-dist
    - run: vendor/bin/sentinel scan . --no-progress
```

The build passes when the scan is clean and fails when it isn't.

## How it works, briefly

1. Discover — it walks the paths you gave it, respecting ignores and file
   types.
2. Parse — each file becomes an AST via `nikic/php-parser`.
3. Analyse — the taint engine follows user input to the sinks.
4. Report — results come out as a console report or JSON.

There's a deeper write-up in [docs/architecture.md](docs/architecture.md) if you
want the full picture.

## Building and testing

```bash
composer analyse   # PHPStan + coding standards + tests
composer test      # just the tests
composer phpstan   # just static analysis
composer cs-check  # just coding standards
```

If you'd like to contribute — a new rule, a test, or a docs fix — please have a
look at [CONTRIBUTING.md](CONTRIBUTING.md). I'd genuinely appreciate it.

## License

MIT — see [LICENSE](LICENSE).
