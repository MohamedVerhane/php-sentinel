# Rules

PHP Sentinel ships with a small, focused rule set. Each rule performs
*static* analysis and reports a finding when user-controlled data reaches a
dangerous sink without obvious sanitization. Findings are always worded as
**potential** vulnerabilities — static analysis cannot prove a vulnerability
exists, nor the absence of one.

> **Tip:** to enable a subset of rules, use the `rules`/`disabled_rules` keys in
> a `.php-sentinel.php` config file, or pass `--severity` to filter by
> severity.

| ID     | Rule                 | Severity | CWE    |
|--------|----------------------|----------|--------|
| SEC001 | SQL Injection        | High     | CWE-89 |
| SEC002 | Cross-Site Scripting | Medium   | CWE-79 |
| SEC003 | Command Injection    | High     | CWE-78 |
| SEC004 | File Inclusion       | High     | CWE-98 |
| SEC005 | Unsafe File Upload   | Medium   | CWE-434 |

---

## SEC001 — SQL Injection

**Severity:** High · **CWE:** CWE-89

### Detection

Flags calls where user-controlled input is concatenated or interpolated into a
SQL query that is then executed. Supported sinks:

- Functions: `query`, `exec`, `multi_query`, `mysqli_query`, `mysqli_multi_query`.
- Methods: `->query()`, `->exec()`, `->multi_query()`.

Calls that use parameterised/prepared statements (e.g. `prepare()` +
`execute()`) are **not** flagged, because parameters are bound separately from
the query text.

### Fix

Use prepared statements with bound parameters:

```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => $_GET['id']]);
```

Never concatenate or interpolate user input into the SQL text, and apply strict
allow-list validation when a dynamic identifier or keyword must be used.

---

## SEC002 — Cross-Site Scripting (XSS)

**Severity:** Medium · **CWE:** CWE-79

### Detection

Flags places where user-controlled input reaches HTML output without escaping
for an HTML context. Supported sinks:

- `echo`, `print`
- `printf`, `sprintf`, `vprintf` arguments

Values passed through HTML-escaping functions (e.g. `htmlspecialchars`,
`htmlentities`) are treated as sanitized and not flagged.

### Fix

Encode all dynamic output with context-appropriate escaping:

```php
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
```

Prefer a template engine that escapes by default, and apply a
Content-Security-Policy to limit the impact of injection.

---

## SEC003 — Command Injection

**Severity:** High · **CWE:** CWE-78

### Detection

Flags user-controlled input reaching shell-execution sinks without escaping.
Supported sinks:

- Functions: `system`, `exec`, `shell_exec`, `passthru`, `proc_open`, `popen`.
- Backtick shell execution `` `...` ``.

Calls whose command is a constant or passed through `escapeshellarg` /
`escapeshellcmd` are not flagged.

### Fix

Avoid invoking a shell entirely — prefer high-level APIs that do not run shell
commands. If a shell is unavoidable, pass arguments via an array (e.g.
`proc_open`) or escape arguments with `escapeshellarg`, and never interpolate
raw input.

---

## SEC004 — File Inclusion

**Severity:** High · **CWE:** CWE-98

### Detection

Flags `include`, `include_once`, `require` and `require_once` statements whose
path is influenced by user-controlled input (Local/Remote File Inclusion).

### Fix

Never use user input directly in include/require paths. Resolve paths against an
explicit allow-list of known values, disable `allow_url_include`, and avoid
dynamic include paths whenever possible.

---

## SEC005 — Unsafe File Upload

**Severity:** Medium · **CWE:** CWE-434

### Detection

Flags two classes of risky `move_uploaded_file()` usage:

1. **User-controlled destination** — the destination/name is derived from
   `$_FILES[...]['name']` without generating a safe random name.
2. **Missing validation** — the call occurs in a scope with no detectable file
   type / MIME / extension validation (e.g. no `finfo_file`, `getimagesize`,
   `pathinfo`, `in_array` MIME checks, etc.).

### Fix

Validate uploads: check the MIME type and real file content (e.g.
`finfo_file` / `getimagesize`), whitelist allowed extensions and MIME types,
generate a random destination name (never trust `$_FILES['name']`), store
uploads outside the web root, and disable execution of uploaded files.
