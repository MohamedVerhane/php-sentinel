# Rules

PHP Sentinel ships with a small, focused set of checks. They're all static: each
one looks at the code without running it and reports when user-controlled data
finds its way to a dangerous spot without any obvious sanitization along the
way.

One thing worth saying up front: every finding is worded as a potential
problem. A static scanner can't prove that something is a real vulnerability,
and it can't prove that your code is safe either. It's there to point you at the
places worth a second look, not to hand down a verdict.

> Tip: if you only want some of these running, use the `rules` /
> `disabled_rules` keys in a `.php-sentinel.php` config file, or narrow things
> down with `--severity` to a specific severity and above.

| ID     | Rule                 | Severity | CWE    |
|--------|----------------------|----------|--------|
| SEC001 | SQL Injection        | High     | CWE-89 |
| SEC002 | Cross-Site Scripting | Medium   | CWE-79 |
| SEC003 | Command Injection    | High     | CWE-78 |
| SEC004 | File Inclusion       | High     | CWE-98 |
| SEC005 | Unsafe File Upload   | Medium   | CWE-434 |

---

## SEC001 — SQL Injection

Severity: High · CWE: CWE-89

### What it looks for

It flags calls where user input is glued into a SQL query — either through
string concatenation or interpolation — and that query is then executed. The
sinks it watches are:

- Functions: `query`, `exec`, `multi_query`, `mysqli_query`, `mysqli_multi_query`.
- Methods: `->query()`, `->exec()`, `->multi_query()`.

Calls that go through prepared statements (`prepare()` + `execute()`) are left
alone, because with those the parameters are bound separately from the SQL text
itself.

### How to fix it

Use prepared statements with bound parameters:

```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => $_GET['id']]);
```

Just don't concatenate or interpolate user input into the SQL string. If you
really need a dynamic identifier or keyword, validate it against a strict
allow-list rather than passing raw input.

---

## SEC002 — Cross-Site Scripting (XSS)

Severity: Medium · CWE: CWE-79

### What it looks for

It flags spots where user input reaches HTML output without being escaped for
an HTML context. The sinks are:

- `echo`, `print`
- arguments passed to `printf`, `sprintf`, `vprintf`

Values that go through HTML-escaping functions such as `htmlspecialchars` or
`htmlentities` count as handled, so they won't be reported.

### How to fix it

Escape anything dynamic when you output it, using escaping that matches the
context:

```php
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
```

If you can, lean on a template engine that escapes by default, and add a
Content-Security-Policy so that even a slip doesn't do as much damage.

---

## SEC003 — Command Injection

Severity: High · CWE: CWE-78

### What it looks for

It flags user input reaching shell-execution sinks without escaping. The sinks:

- Functions: `system`, `exec`, `shell_exec`, `passthru`, `proc_open`, `popen`.
- Backtick shell execution `` `...` ``.

Calls where the command is a fixed constant, or is passed through
`escapeshellarg` / `escapeshellcmd`, aren't reported.

### How to fix it

Best of all, avoid starting a shell in the first place — there's usually a
higher-level API that does the job without one. If you can't avoid it, pass
arguments as an array (for example to `proc_open`) or at least escape each one
with `escapeshellarg`. Never interpolate raw input straight into a command.

---

## SEC004 — File Inclusion

Severity: High · CWE: CWE-98

### What it looks for

It flags `include`, `include_once`, `require`, and `require_once` statements
where the path is built from user input — that's your Local/Remote File
Inclusion territory.

### How to fix it

Don't let user input anywhere near an include/require path. Resolve paths
against an explicit allow-list of known-good values, keep `allow_url_include`
switched off, and steer clear of dynamic includes whenever you can.

---

## SEC005 — Unsafe File Upload

Severity: Medium · CWE: CWE-434

### What it looks for

It flags two kinds of risky `move_uploaded_file()` usage:

1. User-controlled destination — the destination or file name comes from
   `$_FILES[...]['name']` without a safe random name being generated instead.
2. Missing validation — the call happens in a scope where there's no
   detectable file-type / MIME / extension check (no `finfo_file`,
   `getimagesize`, `pathinfo`, or MIME `in_array` checks, and so on).

### How to fix it

Validate the upload before moving it: check the actual MIME type and file
content (`finfo_file` / `getimagesize`), whitelist allowed extensions and MIME
types, and use a randomly generated name rather than trusting
`$_FILES['name']`. Keep uploads outside the web root, and make sure the web
server can't execute whatever lands in the upload directory.
