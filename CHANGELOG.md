# Changelog

All notable changes to PHP Sentinel are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Taint-aware static analysis engine based on `nikic/php-parser`.
- Command-line scanner (`sentinel scan`) with console and JSON output.
- Bundled security rules: SEC001 (SQL Injection), SEC002 (Cross-Site Scripting),
  SEC003 (Command Injection), SEC004 (File Inclusion), SEC005 (Unsafe File
  Upload).
- Sanitizer-aware, per-category taint tracking.
- Immutable configuration with defaults, `.php-sentinel.php` file support and
  CLI overrides.
- Severity thresholds and exit codes (0 = clean, 1 = findings, 2 = error).
- PHPUnit test suite with positive and negative fixtures.
- PHPStan (level 8) and PHP_CodeSniffer (PSR-12) integration.
- Documentation: README, architecture, rules, contributing, security, and this
  changelog.
