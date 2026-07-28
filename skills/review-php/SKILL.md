---
name: review-php
description: Use when reviewing or auditing PHP code - .php files, a composer.json project, "review this PHP app", "audit this endpoint", "check this before I deploy" - covering superglobal data flow into sinks, unserialize on untrusted input, local and remote file inclusion, weak session configuration, SQL built by concatenation, and missing output escaping.
---

# Review PHP

Correctness and security review for PHP. PHP's defaults are permissive and its superglobals put
attacker-controlled data one variable away from every sink in the file, so data flow is where the
review lives. The checklist runs whether or not any tool is installed.

## Procedure

Follow `../../references/procedure.md`. Probe, scope, run what exists, walk the checklist by hand,
score per `../../references/rubric.md`, emit both artifacts.

## Capability probe

```bash
command -v php
command -v phpstan
command -v composer
```

| Tool | Invocation | If absent |
|---|---|---|
| `php -l` | `php -l <file>` (one file per invocation) | install PHP; nothing else here runs without it |
| `phpstan` | `phpstan analyse --level max <paths>` | `composer require --dev phpstan/phpstan`, or `vendor/bin/phpstan` if already vendored |
| `composer audit` | `composer audit` (needs a `composer.lock` in scope) | `composer install` first, or note the project does not use Composer |

Several missing at once? The suite ships `review-tools.sh`, which probes and installs the whole
toolchain in one pass. **Name it in `## Checks skipped` and leave running it to the user**: a review
reports, it does not install.

Check `vendor/bin/` before concluding a tool is absent: PHP projects vendor their tooling far more
often than they install it globally.

`php -l` reports syntax errors only; a clean lint says nothing about the checklist below. A missing
`composer.lock` means `composer audit` did not run: that is a skipped check with the reason "no
lockfile in scope", not a clean dependency report.

## Checklist

| ID | Look for | Why it matters | Fix direction |
|---|---|---|---|
| **PHP-01** | `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `$_SERVER['HTTP_*']` reaching a sink with no validation in between: `exec`/`shell_exec`/`system`/`passthru`, `file_get_contents`, `fopen`, `mail`, `header`, `eval`, a query, or an `include`. | These are the entry points for everything else on this list. `$_SERVER` values with an `HTTP_` prefix are attacker-controlled too, which reviewers routinely forget. Every superglobal is a string of unknown shape until something checks it. | Validate at the entry point (`filter_input` with an explicit filter, an integer cast where an ID is expected, an allow-list where a choice is expected) and pass the validated value on. Escaping at the sink is the second layer, not the first. |
| **PHP-02** | `unserialize` on anything from a cookie, request body, cache entry, or uploaded file, with or without `allowed_classes`. | Deserialisation instantiates objects and runs their magic methods (`__wakeup`, `__destruct`), so a crafted payload chains into file writes or command execution. This is RCE, not information disclosure. | `json_decode` for data interchange. Where PHP serialisation is unavoidable, pass `['allowed_classes' => false]` and sign the payload with an HMAC that is verified before unserialising. |
| **PHP-03** | `include`, `include_once`, `require`, `require_once`, `file_get_contents`, `fopen`, or `readfile` with a variable path component, especially `include $_GET['page'] . '.php'`. | A `../` sequence reads any file the process can (`/etc/passwd`, `.env`, config with DB credentials); a null byte or an appended extension can be worked around; with `allow_url_include` on, a remote URL is direct code execution. | Map the request value through a fixed allow-list array to a literal path. Never concatenate request data into an include path, and never rely on `basename` alone. |
| **PHP-04** | `session_start()` with no hardening (`session.cookie_httponly` off, `cookie_secure` off, `cookie_samesite` unset, `use_strict_mode` off) or no `session_regenerate_id` after a privilege change such as login. | Without `httponly` any XSS steals the session; without `secure` it leaks over plain HTTP; without `use_strict_mode` an attacker-supplied session ID is accepted (session fixation); without regeneration on login, a pre-auth ID keeps working post-auth. | Set the cookie params before `session_start()` (`httponly` and `secure` true, `samesite` `Lax` or `Strict`, `use_strict_mode` on) and call `session_regenerate_id(true)` immediately after any authentication or privilege change. |
| **PHP-05** | A query string built with `.`, `"$var"` interpolation, `sprintf`, or `implode` around any value that did not come from a literal, including values that made a round trip through the database. | SQL injection: read any table, write any row, and on many configurations reach the filesystem. `mysqli_real_escape_string` is not equivalent to a bound parameter and fails on unquoted numeric contexts. | Prepared statements with bound parameters (`PDO::prepare` + `execute`, or `mysqli` bind). Where an identifier or sort direction must vary, resolve it through an allow-list of literal strings. |
| **PHP-06** | `echo`/`print`/interpolation of a variable into HTML with no `htmlspecialchars`; output into a JS block, an HTML attribute, or a URL context escaped with the HTML-only helper; `\|raw` in a template. | Stored or reflected XSS. Context matters: HTML escaping inside a `<script>` block or an unquoted attribute does not prevent the break-out, so "it is escaped" is not by itself a defence. | `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` for HTML and attributes; `json_encode` with `JSON_HEX_TAG\|JSON_HEX_AMP` for values entering JavaScript; `rawurlencode` for URL components. Escape at output, for the destination context. |

Beyond the checklist, also weigh: `==` where `===` is needed (PHP's loose comparison bites on
`"0e123" == "0"` in hash checks), `md5`/`sha1` for passwords instead of `password_hash`, uploads
trusted by `$_FILES['type']` or extension, `extract()` on request data, error display enabled in
production, and missing authorisation checks on endpoints that have authentication.

## Output

Both artifacts, always:

1. **Human report** per the skeleton in `../../references/procedure.md`, ending in a
   `## Checks skipped` table with reason and install hint for every tool that did not run.
2. **Agent prompt block** per `../../references/agent-prompt.md`, all severities, omitted entirely
   when there are no findings.

Derive the block's validation line from the probe. With everything present:
`php -l <changed files> && phpstan analyse --level max <paths>`. With only PHP itself: `php -l`
per changed file, which always works.

## Common mistakes

- **Following the sink and not the source.** A `$_GET` three assignments upstream is the same
  vulnerability as one used inline. Trace the variable back before deciding it is safe.
- **Accepting escaping as validation.** `htmlspecialchars` on output does not make an unvalidated
  path safe for `include`, and an escape for the wrong context is not an escape.
- **Scoring `unserialize` on untrusted input as Medium.** It is code execution. Critical.
- **Assuming no tooling means no review.** The whole checklist is readable by eye, and `php -l` is
  always available. Record what did not run in `## Checks skipped` and review anyway.
