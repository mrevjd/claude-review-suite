<?php
// CLEAN-FIXTURE -- the same six situations as vulnerable.php, written correctly.
// A review of this file must produce no Critical and no High findings.

declare(strict_types=1);

// PHP-04: cookie params are hardened before the session starts, strict mode rejects
// attacker-supplied IDs, and the ID is regenerated on any privilege change (see login()).
session_set_cookie_params([
    'httponly' => true,
    'secure' => true,
    'samesite' => 'Strict',
    'path' => '/',
]);
ini_set('session.use_strict_mode', '1');
session_start();

function connect(): PDO
{
    return new PDO(
        'mysql:host=localhost;dbname=app;charset=utf8mb4',
        getenv('DB_USER') ?: '',
        getenv('DB_PASS') ?: '',
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false],
    );
}

function login(PDO $db): bool
{
    // PHP-01: validated at the entry point rather than escaped at the sink.
    $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
    $password = $_POST['password'] ?? '';

    if ($email === false || $email === null || $password === '') {
        return false;
    }

    // PHP-05: prepared statement with a bound parameter. The value never reaches the SQL text.
    $stmt = $db->prepare('SELECT id, role, pass_hash FROM users WHERE email = ?');
    $stmt->execute([$email]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($row === false || !password_verify($password, $row['pass_hash'])) {
        return false;
    }

    // PHP-04: a session ID fixed before login cannot survive it.
    session_regenerate_id(true);
    $_SESSION['uid'] = (int) $row['id'];
    $_SESSION['role'] = (string) $row['role'];

    return true;
}

function restorePreferences(): array
{
    // PHP-02: JSON instead of PHP serialisation, so no class is instantiated and no magic method
    // runs. Decoded to an array, never an object.
    $raw = $_COOKIE['prefs'] ?? '';
    if ($raw === '') {
        return [];
    }

    $decoded = json_decode($raw, true, 8, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);

    return is_array($decoded) ? $decoded : [];
}

function renderPage(): void
{
    // PHP-03: the request value selects from a fixed map of literal paths. Nothing from the request
    // is ever concatenated into the include, so traversal has nothing to traverse.
    $pages = [
        'home' => 'home.php',
        'about' => 'about.php',
        'pricing' => 'pricing.php',
    ];

    $requested = $_GET['page'] ?? 'home';
    $file = $pages[$requested] ?? $pages['home'];

    include __DIR__ . '/pages/' . $file;
}

function exportReport(): void
{
    // PHP-01: the month is validated to a known shape, then passed as a separate argument rather
    // than interpolated into a shell string.
    $month = filter_input(INPUT_GET, 'month', FILTER_VALIDATE_REGEXP, [
        'options' => ['regexp' => '/^\d{4}-\d{2}$/'],
    ]);

    if ($month === false || $month === null) {
        http_response_code(400);
        echo 'invalid month';
        return;
    }

    $cmd = escapeshellcmd('/usr/local/bin/report') . ' --month=' . escapeshellarg($month);
    system($cmd);
}

function showProfile(PDO $db): void
{
    $uid = (int) ($_SESSION['uid'] ?? 0);
    $stmt = $db->prepare('SELECT display_name, bio FROM users WHERE id = ?');
    $stmt->execute([$uid]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user === false) {
        http_response_code(404);
        return;
    }

    // PHP-06: escaped at output for the destination context -- HTML entities for the heading,
    // JSON with hex flags for the value that lands inside a script block.
    echo '<h1>' . htmlspecialchars((string) $user['display_name'], ENT_QUOTES, 'UTF-8') . '</h1>';
    echo '<script>const bio = '
        . json_encode((string) $user['bio'], JSON_HEX_TAG | JSON_HEX_AMP | JSON_THROW_ON_ERROR)
        . ';</script>';
}

$db = connect();
login($db);
restorePreferences();
renderPage();
exportReport();
showProfile($db);
