<?php
// Differential tests: the vulnerable PHP must actually misbehave where its VULN comments say it
// does, and clean.php must not.
//
// Run with: php tests/fixtures/php/differential.php
//
// Neither fixture can simply be included -- both call connect() at the bottom, which opens a real
// PDO to a database that does not exist here. So each defect is exercised by reproducing the
// fixture's own construct against a sqlite in-memory DB and asserting the behaviour diverges. The
// constructs below are copied from the fixtures; validate.py's ANCHOR lines are what keep the two
// in step, and a divergence here means the copy has drifted and must be resynced.

declare(strict_types=1);

$failures = 0;

function check(string $name, callable $fn): void
{
    global $failures;
    try {
        $fn();
        echo "  pass  {$name}\n";
    } catch (Throwable $e) {
        echo "  FAIL  {$name}: " . $e->getMessage() . "\n";
        $failures++;
    }
}

function assertTrue(bool $cond, string $msg): void
{
    if (!$cond) {
        throw new RuntimeException($msg);
    }
}

function seedDb(): PDO
{
    $db = new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $db->exec('CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, role TEXT, pass_hash TEXT)');
    $stmt = $db->prepare('INSERT INTO users (email, role, pass_hash) VALUES (?, ?, ?)');
    $stmt->execute(['victim@example.com', 'admin', password_hash('correct horse', PASSWORD_DEFAULT)]);
    return $db;
}

// PHP-05: the vulnerable query is assembled by concatenation, so an injected payload changes which
// row -- and whose pass_hash -- is compared. The clean one binds the value.
check('PHP-05 vulnerable query is injectable', function () {
    $db = seedDb();
    $email = "nobody@example.com' OR '1'='1";               // the fixture's own attack string
    $sql = "SELECT id, role, pass_hash FROM users WHERE email = '" . $email . "'";
    $row = $db->query($sql)->fetch(PDO::FETCH_ASSOC);
    assertTrue($row !== false, 'injection returned no row -- PHP-05 no longer fires');
    // The injected row is the victim's, not the non-existent address the attacker supplied: the
    // OR clause widened the match past the email predicate entirely.
    assertTrue($row['role'] === 'admin', 'injection did not reach the victim row');
});

check('PHP-05 clean query resists the same payload', function () {
    $db = seedDb();
    $stmt = $db->prepare('SELECT id, role, pass_hash FROM users WHERE email = ?');
    $stmt->execute(["nobody@example.com' OR '1'='1"]);
    assertTrue($stmt->fetch(PDO::FETCH_ASSOC) === false, 'bound parameter should match nothing');
});

// PHP-02: unserialize on client-controlled data instantiates classes and runs magic methods; the
// clean counterpart decodes JSON, which cannot construct an object.
class PrefsProbe
{
    public static bool $magicRan = false;
    public function __wakeup(): void
    {
        self::$magicRan = true;
    }
}

check('PHP-02 unserialize runs a magic method on client data', function () {
    PrefsProbe::$magicRan = false;
    $payload = base64_encode(serialize(new PrefsProbe()));
    unserialize(base64_decode($payload));                    // the fixture's own construct
    assertTrue(PrefsProbe::$magicRan, '__wakeup did not run -- PHP-02 no longer fires');
});

check('PHP-02 json_decode constructs no object', function () {
    PrefsProbe::$magicRan = false;
    $decoded = json_decode('{"theme":"dark"}', true, 8, JSON_THROW_ON_ERROR);
    assertTrue(is_array($decoded), 'clean path must yield an array');
    assertTrue(!PrefsProbe::$magicRan, 'no magic method may run on the clean path');
});

/** Resolve . and .. segments without touching the filesystem, so the target need not exist. */
function normalisePath(string $path): string
{
    $out = [];
    foreach (explode('/', $path) as $seg) {
        if ($seg === '' || $seg === '.') {
            continue;
        }
        if ($seg === '..') {
            array_pop($out);
            continue;
        }
        $out[] = $seg;
    }
    return '/' . implode('/', $out);
}

// PHP-03: traversal escapes the pages directory. The assertion is "escapes", not "reaches
// /etc/passwd" -- how far up four `..` segments actually land depends on how deep the fixture sits
// in the tree, so asserting a specific absolute target would make this test a function of the
// repository's directory depth rather than of the defect.
check('PHP-03 vulnerable include path escapes its directory', function () {
    $pagesDir = normalisePath(__DIR__ . '/pages');
    $page = '../../../../etc/passwd';
    $target = normalisePath(__DIR__ . '/pages/' . $page . '.php');  // the fixture's own construct
    assertTrue(!str_starts_with($target, $pagesDir . '/'),
        "traversal stayed inside the pages dir ({$target}) -- PHP-03 no longer fires");
    assertTrue(str_ends_with($target, '/etc/passwd.php'),
        "expected the appended .php suffix to survive, got {$target}");
});

check('PHP-03 clean allow-list cannot be traversed', function () {
    $pages = ['home' => 'home.php', 'about' => 'about.php', 'pricing' => 'pricing.php'];
    $file = $pages['../../../../etc/passwd'] ?? $pages['home'];
    assertTrue($file === 'home.php', 'unknown key must fall back to a literal path');
});

// PHP-01: the month reaches a shell sink. Asserted on the composed command string rather than by
// running it -- the test must not execute an injected command to prove it would.
check('PHP-01 vulnerable command string carries the injection', function () {
    $month = '2024; rm -rf /var/www';
    $cmd = '/usr/local/bin/report --month=' . $month;        // the fixture's own construct
    assertTrue(str_contains($cmd, '; rm -rf'),
        'shell metacharacters were neutralised -- PHP-01 no longer fires');
});

check('PHP-01 clean command escapes the argument', function () {
    $month = '2024; rm -rf /var/www';
    $cmd = escapeshellcmd('/usr/local/bin/report') . ' --month=' . escapeshellarg($month);
    assertTrue(!str_contains($cmd, '; rm -rf /var/www') || str_contains($cmd, "'"),
        'the argument must be quoted so the shell cannot split it');
    assertTrue(str_contains($cmd, "'2024; rm -rf /var/www'"), 'expected a single-quoted argument');
});

// PHP-06: unescaped output. Both sinks in the fixture are covered -- HTML context and JS context,
// because escaping correctly for one and not the other is the trap the row exists for.
check('PHP-06 vulnerable output is unescaped in both contexts', function () {
    $name = '<script>alert(1)</script>';
    $html = '<h1>' . $name . '</h1>';                        // the fixture's own construct
    assertTrue(str_contains($html, '<script>'),
        'markup was escaped -- PHP-06 no longer fires');

    $bio = '";alert(1);//';
    $js = '<script>const bio = "' . $bio . '";</script>';
    assertTrue(str_contains($js, '";alert(1);//'), 'JS context escape is missing as planted');
});

check('PHP-06 clean output escapes for each context', function () {
    $name = '<script>alert(1)</script>';
    $html = '<h1>' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '</h1>';
    assertTrue(!str_contains($html, '<script>'), 'htmlspecialchars must neutralise the tag');

    $bio = '";alert(1);//';
    $js = '<script>const bio = '
        . json_encode($bio, JSON_HEX_TAG | JSON_HEX_AMP | JSON_THROW_ON_ERROR) . ';</script>';
    assertTrue(!str_contains($js, '";alert(1);//'), 'json_encode must neutralise the break-out');
});

// PHP-04 has no check here on purpose. A session's cookie flags cannot be compared within one
// process -- session_start() is not repeatable -- and a test that asserts nothing while printing
// "pass" is worse than an acknowledged gap. validate.py's ANCHOR on the ini_set calls and
// ANCHOR-ABSENT on session_regenerate_id are what hold that row.

echo "\n";
if ($failures > 0) {
    echo "{$failures} differential failure(s)\n";
    exit(1);
}
echo "php differential tests passed: vulnerable.php and clean.php diverge where they should\n";
