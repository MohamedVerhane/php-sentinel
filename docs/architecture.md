# Architecture

This page is for people digging into the code — whether you're fixing a bug,
adding a rule, or just trying to make sense of how everything fits together.
It's a plain-language tour of how PHP Sentinel is organised.

## The big picture

Everything flows in one direction, roughly:

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

You point it at some paths, it finds the PHP files, parses each one into a
tree, runs the rules over that tree, and hands the results to a report
renderer. That's the whole loop.

## Where things live

| Path                    | Responsibility                                              |
|-------------------------|-------------------------------------------------------------|
| `bin/sentinel`          | The executable you actually run. Glues the console app together. |
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

## The ideas underneath

### Parsing, not executing

Every file is read with `nikic/php-parser` and turned into an Abstract Syntax
Tree. That's important: the scanner never includes, requires, or runs the code
it's looking at — the parser just reads text. If a file has a parse error,
that's recorded as a diagnostic and the scan keeps going instead of dying.

### Taint analysis

The heart of it is `TaintAnalyzer`, which walks the tree in order and asks one
question about every expression: is this derived from user-controlled input?

Three ideas make that work:

- Sources — the PHP superglobals: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`,
  `$_SERVER`, `$_FILES`.
- Propagation — taint spreads through assignments (including array elements,
  list destructuring and compound assignment), concatenation, string
  interpolation, casts, property/array access, and function/static-call
  arguments.
- Sanitizers — a set of functions that neutralise taint for a particular sink
  category (for example `htmlspecialchars` for XSS, `escapeshellarg` for
  command injection). Sanitization is tracked per category, so cleaning up for
  one sink type won't accidentally silence a finding for another.

Rules poke at the analyzer through two helpers, `isDangerous($expr, $category)`
and `sourcesOf($expr)`, both in `src/DataFlow/TaintAnalyzer.php`.

### Rules

Each rule implements `RuleInterface` and gets registered in `RuleRegistry`. The
engine calls every enabled rule for each AST node, and each rule hands back a
list of `Finding` objects. The detection specifics for each bundled rule live in
[docs/rules.md](rules.md).

Want to add your own rule? The steps are short:

1. Create `src/Rules/MyRule.php` implementing `RuleInterface` (extend
   `AbstractRule` to reuse the shared finding builder).
2. Register it in `RuleRegistry::withDefaultRules()`.
3. Optionally add its ID to `Configuration::defaults()`.
4. Add a positive and a negative fixture under `tests/Fixtures/`, plus a test
   class for it.

### Findings and severity

A `Finding` is a small immutable object that carries the rule ID, title,
message, description, recommendation, CWE, where it was found (file/line/column)
and the offending snippet of code. `Severity` is an ordered enum — `INFO` <
`LOW` < `MEDIUM` < `HIGH` < `CRITICAL` — which is what lets you filter out
findings below a certain threshold.

### CLI and exit codes

`ScanCommand` pulls together the defaults, an optional config file, and any CLI
flags into one immutable `Configuration`, runs the `Scanner`, and prints a
report. The exit code is the whole way it talks to CI:

| Code | Meaning                            |
|------|------------------------------------|
| `0`  | no findings                        |
| `1`  | findings detected                  |
| `2`  | invalid input / configuration error |

## How configuration gets resolved

From lowest to highest precedence:

1. `Configuration::defaults()`
2. `.php-sentinel.php` config file (loaded from the current directory, or an
   explicit one via `--config`)
3. CLI flags (`--format`, `--severity`, `--ignore`, `--no-progress`,
   `--verbose`)

After the merge you get an immutable `Configuration` handed to the `Scanner`,
so nothing downstream can quietly mutate the decisions made upstream.

## Testing

- Unit tests exercise each rule against small inline snippets of code.
- Integration tests scan the positive (`tests/Fixtures/vulnerable`) and negative
  (`tests/Fixtures/safe`) fixture trees and check finding counts, locations,
  that the JSON output is valid, and the CLI exit codes.

Run the whole lot with `composer analyse`.
