# Contributing

Thanks for your interest in PHP Sentinel! Contributions — bug reports, fixes,
documentation, and new features — are very welcome.

## Getting started

1. Fork the repository and clone your fork.
2. Install dependencies:

   ```bash
   composer install
   ```

3. Run the full checks before and after your changes:

   ```bash
   composer analyse
   ```

   This runs static analysis (PHPStan), coding standards (PHP_CodeSniffer) and
   the test suite (PHPUnit).

## Requirements

- PHP 8.2 or newer.
- Code style: PSR-12 (enforced by `phpcs`).
- All `src/` files use `declare(strict_types=1);`.
- New public APIs should be documented with PHPDoc blocks.
- No debug statements (`var_dump`, `print_r`, `dd`, `dump`) — these are blocked
  by the coding standard.

## Running checks individually

```bash
composer test       # PHPUnit
composer phpstan    # PHPStan, level 8
composer cs-check   # PHP_CodeSniffer
composer cs-fix     # auto-fix coding standard violations
```

## Writing a new rule

1. Create `src/Rules/MyRule.php` implementing `RuleInterface` (extend
   `AbstractRule` for the shared finding builder).
2. Register it in `src/Rules/RuleRegistry::withDefaultRules()`.
3. Optionally add its ID to `Configuration::defaults()`.
4. Add a vulnerable fixture under `tests/Fixtures/vulnerable/` and a safe
   fixture under `tests/Fixtures/safe/`.
5. Add a unit test class under `tests/Rules/` and, if needed, update
   `tests/ScannerIntegrationTest.php`.
6. Document the rule in `docs/rules.md`.

See [docs/architecture.md](docs/architecture.md) for the data-flow concepts used
by rules.

## Testing your changes manually

```bash
php bin/sentinel scan .                       # scan the whole repo
php bin/sentinel scan tests/Fixtures/vulnerable --severity=high
php bin/sentinel scan tests/Fixtures/safe --format=json
```

Exit codes: `0` no findings, `1` findings, `2` error.

## Commit messages

- Use imperative mood ("Add X", "Fix Y").
- Keep the subject line under ~72 characters.
- Reference related issues where relevant.

## Submitting a pull request

- Ensure `composer analyse` passes.
- Describe what the change does and why.
- If it fixes an issue, link it.
- Keep the diff focused on the problem being solved.

Thank you for helping make PHP Sentinel better!
