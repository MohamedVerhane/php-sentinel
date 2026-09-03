# Architecture

This document describes how PHP Sentinel is organised internally. It is aimed
at contributors who want to understand the codebase, fix defects, or add new
capabilities (especially new rules).

## High-level pipeline

```
 CLI (bin/sentinel)
   │
   ▼
 ScanCommand ──► Configuration ──► Scanner
                                      │
                    ┌─────────────────┼────────────────┐
                    ▼                 ▼                ▼
            FileDiscovery       FileScanner       RuleRegistry
            (walk paths)       (parse + rules)   (enabled rules)
                    │                 │
                    │                 ├── PhpParser ──► AST
                    │                 └── TaintAnalyzer (data-flow)
                    │                 └── RuleEngine ──► Finding[]
                    │
                    ▼
               ScanResult ──► Report (Console / JSON)
```

## Directory layout

| Path                    | Responsibility                                              |
|-------------------------|-------------------------------------------------------------|
| `bin/sentinel`          | Executable entry point; glues the Symfony console app.      |
| `src/Application.php`   | Builds the Symfony Console application and wires everything. |
| `src/Command/`          | The `scan` command (CLI arguments, exit codes, config merge).|
| `src/Config/`           | Immutable `Configuration` and the `ConfigurationLoader`.     |
| `src/Discovery/`        | `FileDiscovery` — walks paths, filters by extension/ignore.  |
| `src/Parser/`           | `PhpParser` — tokenizes/parses source into an AST.           |
| `src/DataFlow/`         | `TaintAnalyzer` and the `DataFlowContext` (taint tracking).  |
| `src/Rules/`            | Rules, engine, registry and the shared `AbstractRule`.       |
| `src/Scanner/`          | `FileScanner` (per-file) and `Scanner` (orchestrator).       |
| `src/Report/`           | `Report` abstraction + Console and JSON renderers.           |
| `src/Support/`          | `Finding` and `Severity` value types.                        |
| `src/Exception/`        | Domain exceptions.                                           |
| `tests/`                | PHPUnit tests plus positive/negative fixtures.               |
| `config/rules.php`      | Sample user configuration.                                   |

## Core concepts

### AST-based parsing

Each file is parsed with `nikic/php-parser` into an Abstract Syntax Tree. The
scanner never includes, requires, or executes the source it analyses — the
parser only reads text. Parse failures are captured as diagnostics rather than
aborting the whole scan.

### Taint analysis

`TaintAnalyzer` walks the AST in program order and answers one question: is
this expression derived from user-controlled input?

- Sources — the PHP superglobals: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`,
  `$_SERVER`, `$_FILES`.
- Propagation — taint flows through assignments (including array elements,
  list destructuring and compound assignment), concatenation, string
  interpolation, casts, property/array access, and function/static-call
  arguments.
- Sanitizers — a category-aware set of functions that neutralise taint for a
  specific sink category (e.g. `htmlspecialchars` for XSS, `escapeshellarg` for
  command injection). Sanitization is tracked per category, so sanitizing for
  one sink type does not suppress a finding for another.

Rules query the analyzer via `isDangerous($expr, $category)` and
`sourcesOf($expr)` (see `src/DataFlow/TaintAnalyzer.php`).

### Rules

Each rule implements `RuleInterface` and is registered in `RuleRegistry`. A rule
is invoked for every AST node and returns a list of `Finding` objects. See
`docs/rules.md` for the detection logic of each bundled rule.

To add a new rule:

1. Create `src/Rules/MyRule.php` implementing `RuleInterface` (extend
   `AbstractRule` for the shared finding builder).
2. Register it in `RuleRegistry::withDefaultRules()`.
3. (Optionally) add its ID to `Configuration::defaults()`.
4. Add positive and negative fixtures under `tests/Fixtures/` and a test class.

### Findings and severity

A `Finding` is an immutable value object carrying the rule ID, title, message,
description, recommendation, CWE, source location (file/line/column) and the
offending code snippet. `Severity` is an ordered enum (`INFO` < `LOW` <
`MEDIUM` < `HIGH` < `CRITICAL`) used to filter findings below a threshold.

### CLI and exit codes

`ScanCommand` merges defaults, the optional config file and CLI flags into a
single immutable `Configuration`, runs the `Scanner`, and renders a report. The
exit code contract is:

| Code | Meaning                            |
|------|------------------------------------|
| `0`  | no findings                        |
| `1`  | findings detected                  |
| `2`  | invalid input / configuration error |

## Configuration resolution

Order of precedence (lowest to highest):

1. `Configuration::defaults()`
2. `.php-sentinel.php` config file (autoloaded from the current directory, or
   via `--config`)
3. CLI flags (`--format`, `--severity`, `--ignore`, `--no-progress`,
   `--verbose`)

The merged result is an immutable `Configuration` passed to the `Scanner`.

## Testing

- Unit tests exercise each rule against inline code.
- Integration tests scan the positive (`tests/Fixtures/vulnerable`) and negative
  (`tests/Fixtures/safe`) fixture trees and assert finding counts, locations,
  JSON validity and CLI exit codes.

Run everything with `composer analyse`.
