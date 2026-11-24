<?php
/**
 * GitDeploy - single-file Git clone / pull tool for cPanel (shared hosting) servers.
 *
 * Upload this file anywhere inside public_html, open it in the browser, log in,
 * enter repo URL + credentials (token), pick a branch, Clone or Pull.
 *
 * SECURITY:
 *  - Change the password hash below before using on a real server!
 *      php -r 'echo password_hash("YourNewPassword", PASSWORD_DEFAULT);'
 *  - Delete or rename this file when you are done, or protect it with .htaccess/IP rules.
 *  - Credentials are only stored if you tick "Save" (AES-256-GCM encrypted file, placed above the web root when possible).
 *    They are passed to git through an
 *    askpass helper + environment variables, never written to .git/config.
 */

// ======================= CONFIG =======================
// Default password: Admin@12345  (TESTING ONLY - change it!)
const ADMIN_PASSWORD_HASH = '$2y$12$ETv9.CL1JPHDXLaGmtNK5.gFjNnAfWql/dNUVD4oT.lvIaAxhc5O2';

// Folder where the repo lives. Empty = auto-detect: the nearest parent folder containing .git,
// else the project root (parent of /public if this file is inside "public"), else the folder of this file.
// Example: '/home/cpaneluser/public_html/myapp'
const DEFAULT_TARGET_DIR = '';

// Optional: restrict the tool to these IPs (empty array = allow all)
const ALLOWED_IPS = [];

const MAX_LOGIN_FAILS = 5;      // lock out after N failed logins...
const LOCKOUT_SECONDS = 900;    // ...for this many seconds (per IP)
// ======================================================

error_reporting(E_ALL);
ini_set('display_errors', '0');
@set_time_limit(900);

if (ALLOWED_IPS && !in_array($_SERVER['REMOTE_ADDR'] ?? '', ALLOWED_IPS, true)) {
    http_response_code(403);
    exit('Forbidden');
}

header('X-Frame-Options: DENY');
header('X-Robots-Tag: noindex, nofollow');
header('Cache-Control: no-store');

session_name('gitdeploy');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '',
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

// ---------- login throttling (file based, per IP) ----------
function fail_file() { return sys_get_temp_dir() . '/gitdeploy_' . md5($_SERVER['REMOTE_ADDR'] ?? 'x') . '.json'; }
function fail_state() {
    $d = @json_decode((string)@file_get_contents(fail_file()), true);
    return is_array($d) ? $d : ['n' => 0, 't' => 0];
}
function locked_out() {
    $d = fail_state();
    return $d['n'] >= MAX_LOGIN_FAILS && (time() - $d['t']) < LOCKOUT_SECONDS;
}

$flash = '';
if (isset($_POST['login'])) {
    if (locked_out()) {
        $flash = 'Too many failed attempts. Try again later.';
    } elseif (hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? '')) &&
              password_verify((string)($_POST['password'] ?? ''), ADMIN_PASSWORD_HASH)) {
        @unlink(fail_file());
        session_regenerate_id(true);
        $_SESSION['auth'] = true;
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    } else {
        $d = fail_state();
        if ((time() - $d['t']) >= LOCKOUT_SECONDS) $d['n'] = 0;
        $d['n']++; $d['t'] = time();
        @file_put_contents(fail_file(), json_encode($d));
        sleep(1);
        $flash = 'Wrong password.';
    }
}
if (isset($_GET['logout'])) {
    $_SESSION = [];
    session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

// ---------- layout ----------
function page_head($title = 'GitDeploy') {
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8">'
       . '<meta name="viewport" content="width=device-width,initial-scale=1">'
       . '<meta name="robots" content="noindex,nofollow"><title>' . h($title) . '</title><style>
:root{--bg:#f4f5f7;--card:#fff;--tx:#1f2430;--mut:#6b7280;--bd:#d9dde4;--pri:#2563eb;--ok:#15803d;--er:#b91c1c;--code:#0f172a}
@media(prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#181c25;--tx:#e6e8ee;--mut:#9aa3b2;--bd:#2c3340;--pri:#3b82f6;--ok:#4ade80;--er:#f87171;--code:#05070b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.5 system-ui,sans-serif}
.wrap{max-width:820px;margin:0 auto;padding:16px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:16px;margin-bottom:16px}
h1{font-size:20px;margin:0}h2{font-size:16px;margin:0 0 10px}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
label{display:block;font-size:13px;color:var(--mut);margin:10px 0 3px}
input[type=text],input[type=password],select{width:100%;padding:9px 10px;border:1px solid var(--bd);border-radius:6px;background:var(--bg);color:var(--tx);font:inherit}
.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media(max-width:600px){.row{grid-template-columns:1fr}}
button,.btn{background:var(--pri);color:#fff;border:0;border-radius:6px;padding:9px 16px;font:inherit;cursor:pointer;text-decoration:none;display:inline-block}
button.sec,.btn.sec{background:transparent;color:var(--tx);border:1px solid var(--bd)}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}
pre{background:var(--code);color:#d1d5db;padding:12px;border-radius:6px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:13px;margin:8px 0 0}
.kv{display:grid;grid-template-columns:130px 1fr;gap:4px 10px;font-size:14px}.kv b{color:var(--mut);font-weight:500}
.tag{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;border:1px solid var(--bd)}
.ok{color:var(--ok)}.er{color:var(--er)}.mut{color:var(--mut);font-size:13px}
.chk{display:flex;gap:8px;align-items:center;margin-top:10px;font-size:14px;color:var(--tx)}
.chk input{width:auto}
</style></head><body><div class="wrap">';
}
function page_foot() { echo '</div></body></html>'; }

if (empty($_SESSION['auth'])) {
    page_head('GitDeploy - Login');
    echo '<div class="card" style="max-width:360px;margin:60px auto"><h1>GitDeploy</h1>
    <form method="post" autocomplete="off"><input type="hidden" name="csrf" value="' . h($_SESSION['csrf']) . '">
    <label>Admin password</label><input type="password" name="password" autofocus required>';
    if ($flash) echo '<p class="er">' . h($flash) . '</p>';
    echo '<div class="actions"><button name="login" value="1">Login</button></div></form></div>';
    page_foot();
    exit;
}

// ================= Git helpers =================
function find_git() {
    foreach (['/usr/local/cpanel/3rdparty/bin/git', '/usr/bin/git', '/usr/local/bin/git', 'git'] as $g) {
        if ($g === 'git' || @is_executable($g)) {
            $out = []; $rc = 1;
            @exec(escapeshellarg($g) . ' --version 2>&1', $out, $rc);
            if ($rc === 0) return $g;
        }
    }
    return null;
}

function mask($text, $cred) {
    if (!empty($cred['pass'])) $text = str_replace($cred['pass'], '***', $text);
    return preg_replace('#(https?://)[^/@\s]+@#i', '$1***@', $text);
}

/** Run git. $cred = ['user'=>..,'pass'=>..] or null. Returns [exitcode, output]. */
function git(array $args, $cwd = null, $cred = null) {
    global $GIT;
    $cmd = escapeshellarg($GIT) . ' -c safe.directory=* -c core.quotepath=false';
    foreach ($args as $a) $cmd .= ' ' . escapeshellarg($a);

    $env = array_merge(getenv() ?: [], [
        'GIT_TERMINAL_PROMPT' => '0',
        'LC_ALL' => 'C',
        'HOME' => getenv('HOME') ?: (function_exists('posix_getpwuid') ? (posix_getpwuid(posix_geteuid())['dir'] ?? __DIR__) : __DIR__),
    ]);
    $askpass = null;
    if ($cred && ($cred['pass'] ?? '') !== '') {
        $askpass = __DIR__ . '/.gitdeploy-askpass-' . bin2hex(random_bytes(4)) . '.sh';
        file_put_contents($askpass, "#!/bin/sh\ncase \"\$1\" in\n*sername*) printf '%s' \"\$GD_USER\";;\n*) printf '%s' \"\$GD_PASS\";;\nesac\n");
        chmod($askpass, 0700);
        $env['GIT_ASKPASS'] = $askpass;
        $env['GD_USER'] = $cred['user'] ?? '';
        $env['GD_PASS'] = $cred['pass'];
        $env['SSH_ASKPASS'] = $askpass;
    }

    if (!function_exists('proc_open')) {
        return [1, 'proc_open() is disabled on this server. Ask your host to enable it.'];
    }
    $p = @proc_open($cmd . ' 2>&1', [1 => ['pipe', 'w']], $pipes, $cwd ?: null, $env);
    if (!is_resource($p)) {
        if ($askpass) @unlink($askpass);
        return [1, 'Could not start git process.'];
    }
    $out = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $rc = proc_close($p);
    if ($askpass) @unlink($askpass);
    return [$rc, trim(mask($out, $cred))];
}

function is_repo($dir) { return is_dir($dir . '/.git') || is_file($dir . '/.git'); }
function dir_empty($dir) { return !is_dir($dir) || count(array_diff(scandir($dir), ['.', '..'])) === 0; }
/** True if the folder holds nothing but this tool itself (and its own temp/store files). */
function dir_only_self($dir) {
    if (!is_dir($dir)) return true;
    foreach (array_diff(scandir($dir), ['.', '..']) as $e) {
        if (realpath($dir . '/' . $e) === realpath(__FILE__) || strpos($e, '.gitdeploy') === 0) continue;
        return false;
    }
    return true;
}

function clean_url($url, &$embedded) {
    $url = trim($url);
    $embedded = null;
    if ($url === '' || $url[0] === '-') return null;
    if (preg_match('#^(https?)://([^/@]+)@(.+)$#i', $url, $m)) {      // strip embedded credentials
        $parts = explode(':', $m[2], 2);
        $embedded = ['user' => urldecode($parts[0]), 'pass' => urldecode($parts[1] ?? '')];
        $url = $m[1] . '://' . $m[3];
    }
    if (!preg_match('#^(https?://|ssh://|git@)[A-Za-z0-9._~:/@%+\-]+$#', $url)) return null;
    return $url;
}

/** Where the project root probably is, e.g. Laravel: this file is in /project/public, repo is /project */
function default_dir() {
    if (DEFAULT_TARGET_DIR !== '') return rtrim(DEFAULT_TARGET_DIR, '/\\');
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {                       // walk up looking for an existing .git
        if (@is_dir($d . '/.git') || @is_file($d . '/.git')) return $d;
        $p = dirname($d);
        if ($p === $d) break;
        $d = $p;
    }
    $parent = dirname(__DIR__);                         // Laravel-style layout: document root is /public
    if (@is_file($parent . '/artisan') || (basename(__DIR__) === 'public' && @is_file($parent . '/composer.json'))) return $parent;
    if (basename(__DIR__) === 'public') return $parent;  // document root is /public: project root is one level up
    return __DIR__;                                       // otherwise check out right here (the web root)
}

function resolve_dir($input) {
    $dir = trim($input) !== '' ? trim($input) : default_dir();
    return rtrim($dir, '/\\');
}

// ---------- optional encrypted credential store ----------
function store_path() {
    $base = is_writable(dirname(__DIR__)) ? dirname(__DIR__) : __DIR__;   // prefer a folder above the web root
    return $base . '/.gitdeploy-store.dat';
}
function store_key() { return hash('sha256', 'gitdeploy|' . ADMIN_PASSWORD_HASH, true); }
function store_load() {
    $raw = @file_get_contents(store_path());
    if (!$raw || !function_exists('openssl_decrypt')) return null;
    $raw = base64_decode($raw);
    if (strlen($raw) < 29) return null;
    $j = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', store_key(), OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16));
    $d = $j === false ? null : json_decode($j, true);
    return is_array($d) ? $d : null;
}
function store_save(array $d) {
    if (!function_exists('openssl_encrypt')) return false;
    $iv = random_bytes(12); $tag = '';
    $c = openssl_encrypt(json_encode($d), 'aes-256-gcm', store_key(), OPENSSL_RAW_DATA, $iv, $tag);
    if ($c === false) return false;
    $ok = @file_put_contents(store_path(), base64_encode($iv . $tag . $c)) !== false;
    if ($ok) @chmod(store_path(), 0600);
    return $ok;
}

// ---------- migrations (multi-framework) ----------
/** Returns null when no supported migration setup is found, else info array. */
function migration_info($dir) {
    $fws = [
        // marker file(s), migration file globs, run command, status command (relative script + args, run with php CLI)
        ['Laravel',         ['artisan'],      ['database/migrations/*.php'],              ['artisan', 'migrate', '--force', '--no-interaction'],                                   ['artisan', 'migrate:status', '--no-interaction'], true],
        ['CodeIgniter 4',   ['spark'],        ['app/Database/Migrations/*.php'],          ['spark', 'migrate'],                                                                    ['spark', 'migrate:status'], true],
        ['Symfony (Doctrine)', ['bin/console'], ['migrations/*.php', 'src/Migrations/*.php'], ['bin/console', 'doctrine:migrations:migrate', '--no-interaction', '--allow-no-migration'], ['bin/console', 'doctrine:migrations:status', '--no-interaction'], true],
        ['Yii 2',           ['yii'],          ['migrations/*.php', 'console/migrations/*.php'], ['yii', 'migrate', '--interactive=0'],                                           ['yii', 'migrate/new', '--interactive=0'], false],
        ['CakePHP',         ['bin/cake'],     ['config/Migrations/*.php'],                ['bin/cake', 'migrations', 'migrate'],                                                   ['bin/cake', 'migrations', 'status'], true],
        ['Phinx',           ['phinx.php', 'phinx.yml', 'phinx.yaml', 'phinx.json'], ['db/migrations/*.php', 'database/migrations/*.php'], ['vendor/bin/phinx', 'migrate'],         ['vendor/bin/phinx', 'status'], false],
    ];
    foreach ($fws as [$name, $markers, $globs, $run, $status, $env]) {
        $has = false;
        foreach ($markers as $m) if (is_file($dir . '/' . $m)) { $has = true; break; }
        if (!$has) continue;
        $n = 0;
        foreach ($globs as $g) $n += count(glob($dir . '/' . $g) ?: []);
        if ($n === 0) continue;
        return ['fw' => $name, 'count' => $n, 'vendor' => is_file($dir . '/vendor/autoload.php'), 'env' => !$env || is_file($dir . '/.env'),
                'run' => $run, 'status' => $status, 'label' => 'php ' . implode(' ', array_slice($run, 0, 3))];
    }
    return null;
}
function find_php() {
    $c = [PHP_BINDIR . '/php', '/usr/local/bin/php', '/usr/bin/php', 'php'];
    foreach ($c as $b) {
        if ($b !== 'php' && !@is_executable($b)) continue;
        $o = []; $rc = 1;
        @exec(escapeshellarg($b) . ' -r "echo PHP_SAPI;" 2>&1', $o, $rc);
        if ($rc === 0 && ($o[0] ?? '') === 'cli') return $b;
    }
    return null;
}
/** Run a migration command: $cmd = [script, args...] executed with the PHP CLI inside $dir. */
function mig_exec($dir, array $cmd) {
    $php = find_php();
    if (!$php) return [1, 'PHP CLI binary not found.'];
    if (!function_exists('proc_open')) return [1, 'proc_open() is disabled.'];
    $line = escapeshellarg($php);
    foreach ($cmd as $a) $line .= ' ' . escapeshellarg($a);
    $p = @proc_open($line . ' 2>&1', [1 => ['pipe', 'w']], $pipes, $dir);
    if (!is_resource($p)) return [1, 'Could not start php.'];
    $out = stream_get_contents($pipes[1]); fclose($pipes[1]);
    return [proc_close($p), trim($out)];
}

// ---------- Laravel .htaccess helpers ----------
const GD_HT_BEGIN = '# BEGIN GitDeploy Laravel';
const GD_HT_END = '# END GitDeploy Laravel';

function is_laravel($dir) { return is_file($dir . '/artisan') && is_file($dir . '/public/index.php'); }

/** Path of this script relative to the project root (or null if it is outside it). */
function self_rel($dir) {
    $d = realpath($dir); $f = realpath(__FILE__);
    if ($d && $f && strpos($f, $d . DIRECTORY_SEPARATOR) === 0) return str_replace('\\', '/', substr($f, strlen($d) + 1));
    return null;
}
function ht_escape($path) { return preg_replace('~([.+?()\[\]{}^$|])~', '\\\\$1', $path); }

function ht_block_public() {
    return GD_HT_BEGIN . "\n" . <<<'HT'
<IfModule mod_rewrite.c>
    <IfModule mod_negotiation.c>
        Options -MultiViews -Indexes
    </IfModule>

    RewriteEngine On

    # Handle Authorization Header
    RewriteCond %{HTTP:Authorization} .
    RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]

    # Handle X-XSRF-Token Header
    RewriteCond %{HTTP:x-xsrf-token} .
    RewriteRule .* - [E=HTTP_X_XSRF_TOKEN:%{HTTP:X-XSRF-Token}]

    # Redirect Trailing Slashes If Not A Folder...
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_URI} (.+)/$
    RewriteRule ^ %1 [L,R=301]

    # Send Requests To Front Controller... (existing files such as gitdeploy.php are served as-is)
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^ index.php [L]
</IfModule>
HT
    . "\n" . GD_HT_END . "\n";
}

function ht_block_root($rel) {
    $ex = $rel ? "    # Keep the deploy tool reachable\n    RewriteRule ^" . ht_escape($rel) . '$ - [L]' . "\n\n" : '';
    return GD_HT_BEGIN . "\n" . <<<HT
# Document root is the project folder: send everything to /public
<IfModule mod_rewrite.c>
    RewriteEngine On

{$ex}    # Already inside /public? leave it alone
    RewriteCond %{REQUEST_URI} !^/public/
    RewriteRule ^(.*)$ public/$1 [L,QSA]
</IfModule>

# Never serve this tool's saved-credential / helper files
<FilesMatch "^\.gitdeploy">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order allow,deny
        Deny from all
    </IfModule>
</FilesMatch>

HT
    . GD_HT_END . "\n";
}

/** What does an .htaccess currently contain? returns [state, text] */
function ht_state($file, $kind) {
    if (!is_file($file)) return ['missing', 'not found'];
    $c = (string)@file_get_contents($file);
    if (strpos($c, GD_HT_BEGIN) !== false) return ['managed', 'contains the GitDeploy Laravel block'];
    if ($kind === 'public' && preg_match('~RewriteRule\s+\^\s+index\.php~i', $c)) return ['ok', 'already has the Laravel front-controller rule'];
    if ($kind === 'root' && preg_match('~RewriteRule\s+\S+\s+public/~i', $c)) return ['ok', 'already routes requests to public/'];
    return ['incomplete', 'exists but has no ' . ($kind === 'public' ? 'Laravel front-controller rule' : 'rule routing to public/')];
}

/** Create / update / append the managed block. Never overwrites other content; backs up first. */
function ht_apply($file, $block, $kind) {
    [$st, $why] = ht_state($file, $kind);
    if ($st === 'ok') return [true, basename(dirname($file)) . "/.htaccess $why - left unchanged."];
    if ($st === 'missing') {
        return @file_put_contents($file, $block) !== false ? [true, "Created $file"] : [false, "Cannot write $file"];
    }
    $c = (string)file_get_contents($file);
    $bak = $file . '.gitdeploy-bak-' . date('YmdHis');
    if (!@copy($file, $bak)) return [false, "Cannot create backup next to $file (folder not writable?)"];
    if ($st === 'managed') {
        $new = preg_replace('~' . preg_quote(GD_HT_BEGIN, '~') . '.*?' . preg_quote(GD_HT_END, '~') . '\R?~s', str_replace(['\\', '$'], ['\\\\', '\\$'], $block), $c, 1);
        $msg = "Updated the GitDeploy block in $file";
    } else {
        $new = rtrim($c) . "\n\n" . $block;
        $msg = "Added the GitDeploy block to the end of $file (existing rules kept)";
    }
    return @file_put_contents($file, $new) !== false ? [true, $msg . "\nBackup: " . basename($bak)] : [false, "Cannot write $file"];
}

// ---------- Laravel storage:link ----------
function storage_state($dir) {
    $l = $dir . '/public/storage';
    if (is_link($l)) return @file_exists($l) ? ['linked', 'public/storage is linked to ' . readlink($l)] : ['broken', 'public/storage is a broken symlink (' . readlink($l) . ')'];
    if (is_dir($l)) return ['dir', 'public/storage is a real folder, not a symlink'];
    if (file_exists($l)) return ['dir', 'public/storage exists and is a file'];
    return ['missing', 'public/storage link does not exist'];
}
function run_storage_link($dir) {
    [$st, $why] = storage_state($dir);
    if ($st === 'linked') return [true, "Already linked - nothing to do.\n$why"];
    if ($st === 'dir') return [false, "$why. Move or remove it first, then run again."];
    if (!is_dir($dir . '/storage/app/public')) @mkdir($dir . '/storage/app/public', 0775, true);
    $args = ['artisan', 'storage:link', '--no-interaction'];
    if ($st === 'broken') { @unlink($dir . '/public/storage'); }
    [$rc, $out] = mig_exec($dir, $args);
    if (storage_state($dir)[0] === 'linked') return [true, $out];
    // fallback when artisan cannot create it (symlink() disabled for CLI, old Laravel, ...)
    $target = '../storage/app/public';
    $ok = function_exists('symlink') && @symlink($target, $dir . '/public/storage');
    if (!$ok && function_exists('exec')) { @exec('cd ' . escapeshellarg($dir . '/public') . ' && ln -s ' . escapeshellarg($target) . ' storage 2>&1'); }
    if (storage_state($dir)[0] === 'linked') return [true, ($out !== '' ? $out . "\n" : '') . 'Created with a direct symlink fallback.'];
    return [false, ($out !== '' ? $out . "\n" : '') . 'Could not create the symlink. Your host may disable symlink(); create it in cPanel Terminal: ln -s ../storage/app/public public/storage'];
}

// ---------- frontend build (npm / yarn / pnpm) ----------
function frontend_info($dir) {
    $f = $dir . '/package.json';
    if (!is_file($f)) return null;
    $j = json_decode((string)@file_get_contents($f), true);
    if (!is_array($j) || empty($j['scripts']['build'])) return null;
    $deps = array_merge($j['dependencies'] ?? [], $j['devDependencies'] ?? []);
    $has = function ($n) use ($deps) { return isset($deps[$n]); };
    $fe = $has('next') ? 'Next.js' : ($has('nuxt') || $has('nuxt3') ? 'Nuxt' : ($has('react') ? 'React' : ($has('vue') ? 'Vue' : ($has('svelte') ? 'Svelte' : ($has('@angular/core') ? 'Angular' : ($has('vite') ? 'Vite' : ($has('laravel-mix') ? 'Laravel Mix' : 'Node')))))));
    if (is_laravel($dir)) $fe = 'Laravel + ' . ($fe === 'Node' ? 'frontend' : $fe);
    $pm = is_file($dir . '/pnpm-lock.yaml') ? 'pnpm' : (is_file($dir . '/yarn.lock') ? 'yarn' : 'npm');
    $lock = is_file($dir . '/package-lock.json') || is_file($dir . '/yarn.lock') || is_file($dir . '/pnpm-lock.yaml');
    return ['label' => $fe, 'pm' => $pm, 'lock' => $lock, 'build' => (string)$j['scripts']['build']];
}
function find_node_tool($name) {
    $home = getenv('HOME') ?: '';
    $c = ['/usr/local/bin/' . $name, '/usr/bin/' . $name, $home . '/.volta/bin/' . $name, $home . '/bin/' . $name];
    foreach (['/opt/cpanel/ea-nodejs*/bin/', $home . '/nodevenv/*/*/bin/', $home . '/.nvm/versions/node/*/bin/'] as $g) {
        $m = glob($g . $name) ?: [];
        rsort($m);
        $c = array_merge($c, $m);
    }
    foreach ($c as $x) if ($x !== '' && @is_executable($x)) return $x;
    $o = []; $rc = 1;
    @exec($name . ' --version 2>&1', $o, $rc);
    return $rc === 0 ? $name : null;
}
/** $what: 'install' | 'build' | 'both'. Returns list of log entries. */
function run_frontend($dir, $fe, $what) {
    $pm = $fe['pm'];
    $tool = find_node_tool($pm) ?: ($pm !== 'npm' ? null : null);
    if (!$tool) return [[$pm . ' not found', false, "Node.js / $pm was not found on this server. In cPanel use \"Setup Node.js App\" (or ask your host to install Node), or build locally and commit the built assets."]];
    $npm = find_node_tool('npm');
    $bins = array_unique(array_filter([dirname($tool), $npm ? dirname($npm) : null, ($n = find_node_tool('node')) ? dirname($n) : null], function ($d) { return $d && $d[0] === '/'; }));
    $home = getenv('HOME') ?: $dir;
    $env = array_merge(getenv() ?: [], ['HOME' => $home, 'CI' => '1', 'npm_config_cache' => $home . '/.npm', 'PATH' => implode(':', $bins) . ':' . (getenv('PATH') ?: '/usr/bin:/bin')]);
    unset($env['NODE_ENV']);   // dev dependencies (vite, etc.) are needed to build
    $q = escapeshellarg($tool);
    $install = $pm === 'npm' ? ($fe['lock'] ? "$q ci" : "$q install") : ($pm === 'yarn' ? "$q install" . ($fe['lock'] ? ' --frozen-lockfile' : '') : "$q install" . ($fe['lock'] ? ' --frozen-lockfile' : ''));
    $build = $pm === 'yarn' ? "$q build" : "$q run build";
    $steps = [];
    if ($what !== 'build') $steps[] = [$pm . ' ' . ($pm === 'npm' && $fe['lock'] ? 'ci' : 'install'), $install];
    if ($what !== 'install') $steps[] = [$pm . ($pm === 'yarn' ? ' build' : ' run build'), $build];
    $log = [];
    foreach ($steps as [$title, $cmd]) {
        if (!function_exists('proc_open')) { $log[] = [$title, false, 'proc_open() is disabled.']; break; }
        $p = @proc_open($cmd . ' 2>&1', [1 => ['pipe', 'w']], $pipes, $dir, $env);
        if (!is_resource($p)) { $log[] = [$title, false, 'Could not start process.']; break; }
        $out = stream_get_contents($pipes[1]); fclose($pipes[1]);
        $rc = proc_close($p);
        $out = trim($out);
        if (strlen($out) > 6000) $out = '... (output truncated)' . "\n" . substr($out, -6000);
        $log[] = [$title, $rc === 0, $out];
        if ($rc !== 0) break;
    }
    return $log;
}

// ---------- composer ----------
function composer_info($dir) {
    if (!is_file($dir . '/composer.json')) return null;
    return ['lock' => is_file($dir . '/composer.lock'), 'vendor' => is_dir($dir . '/vendor')];
}
/** Returns the command prefix (string) to run composer, or null. */
function find_composer($dir) {
    $php = find_php();
    foreach ([$dir . '/composer.phar', (getenv('HOME') ?: '') . '/composer.phar', (getenv('HOME') ?: '') . '/bin/composer.phar'] as $ph) {
        if ($php && @is_file($ph)) return escapeshellarg($php) . ' ' . escapeshellarg($ph);
    }
    foreach (['/usr/local/bin/composer', '/usr/bin/composer', '/opt/cpanel/composer/bin/composer', '/usr/local/cpanel/3rdparty/bin/composer', (getenv('HOME') ?: '') . '/bin/composer'] as $c) {
        if (@is_executable($c)) return escapeshellarg($c);
    }
    $o = []; $rc = 1;
    @exec('composer --version 2>&1', $o, $rc);
    return $rc === 0 ? 'composer' : null;
}
function run_composer($dir, $withDev) {
    $c = find_composer($dir);
    if (!$c) return [1, "Composer not found. Install it in cPanel (Terminal / \"composer\" in Software) or upload composer.phar to the project folder or your home folder."];
    $home = getenv('HOME') ?: (function_exists('posix_getpwuid') ? (posix_getpwuid(posix_geteuid())['dir'] ?? $dir) : $dir);
    $env = array_merge(getenv() ?: [], ['HOME' => $home, 'COMPOSER_HOME' => $home . '/.composer', 'COMPOSER_ALLOW_SUPERUSER' => '1', 'COMPOSER_NO_INTERACTION' => '1']);
    $php = find_php();
    if ($php) $env['PATH'] = dirname($php) . ':' . ($env['PATH'] ?? '/usr/bin:/bin');   // make "php" resolve to the CLI binary
    $cmd = $c . ' install --no-interaction --prefer-dist --optimize-autoloader' . ($withDev ? '' : ' --no-dev') . ' 2>&1';
    if (!function_exists('proc_open')) return [1, 'proc_open() is disabled.'];
    $p = @proc_open($cmd, [1 => ['pipe', 'w']], $pipes, $dir, $env);
    if (!is_resource($p)) return [1, 'Could not start composer.'];
    $out = stream_get_contents($pipes[1]); fclose($pipes[1]);
    return [proc_close($p), trim($out)];
}

function parse_branches($out) {
    $b = [];
    foreach (explode("\n", $out) as $line) {
        if (preg_match('#\srefs/heads/(.+)$#', trim($line), $m)) $b[] = $m[1];
    }
    sort($b);
    return $b;
}

// ================= Request handling =================
$GIT = find_git();
$log = [];       // [title, ok, output]
$notice = '';

$f = $_SESSION['form'] ?? ['url' => '', 'user' => '', 'dir' => '', 'branch' => ''];
$branches = $_SESSION['branches'] ?? [];
$saved = store_load();
if ($saved && empty($_SESSION['form'])) {
    $f = ['url' => $saved['url'] ?? '', 'user' => $saved['user'] ?? '', 'dir' => $saved['dir'] ?? '', 'branch' => $saved['branch'] ?? ''];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if (!hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) {
        http_response_code(400);
        exit('Bad CSRF token');
    }
    $f = [
        'url' => trim($_POST['url'] ?? ''),
        'user' => trim($_POST['user'] ?? ''),
        'dir' => trim($_POST['dir'] ?? ''),
        'branch' => trim($_POST['branch'] ?? ''),
    ];
    $_SESSION['form'] = $f;
    $pass = (string)($_POST['pass'] ?? '');
    $action = $_POST['action'];
    $dir = resolve_dir($f['dir']);

    // optional saved credentials
    if ($action === 'forget') {
        @unlink(store_path());
        $saved = null;
        $notice = 'Saved credentials removed.';
        $action = '';
    }
    if ($pass === '' && $saved && ($saved['pass'] ?? '') !== '' && ($f['user'] === '' || $f['user'] === ($saved['user'] ?? ''))) {
        $pass = $saved['pass'];
        if ($f['user'] === '') $f['user'] = $saved['user'] ?? '';
    }
    if ($action && !empty($_POST['save'])) {
        if (store_save(['url' => $f['url'], 'user' => $f['user'], 'pass' => $pass, 'dir' => $f['dir'], 'branch' => $f['branch']])) {
            $saved = store_load();
            $log[] = ['Credentials saved (encrypted) to ' . store_path(), true, ''];
        } else {
            $log[] = ['Could not save credentials (openssl missing or folder not writable)', false, ''];
        }
    }

    $skipGit = false;
    if (in_array($action, ['migrate', 'migstatus'], true)) {
        $skipGit = true;
        $mi = migration_info($dir);
        if (!$mi) $notice = 'No supported migrations found in this project.';
        elseif (!$mi['vendor']) $notice = 'vendor/ is missing - run "composer install" first.';
        elseif ($action === 'migstatus') { [$rc, $o] = mig_exec($dir, $mi['status']); $log[] = [$mi['fw'] . ': php ' . implode(' ', $mi['status']), $rc === 0, $o]; }
        else { [$rc, $o] = mig_exec($dir, $mi['run']); $log[] = [$mi['fw'] . ': php ' . implode(' ', $mi['run']), $rc === 0, $o]; }
    }

    if ($action === 'composer') {
        $skipGit = true;
        if (!composer_info($dir)) $notice = 'No composer.json found in this folder.';
        else { [$rc, $o] = run_composer($dir, !empty($_POST['with_dev'])); $log[] = ['composer install' . (empty($_POST['with_dev']) ? ' --no-dev' : ''), $rc === 0, $o]; }
    }

    if (in_array($action, ['fe_install', 'fe_build', 'fe_both'], true)) {
        $skipGit = true;
        if (!($fe = frontend_info($dir))) $notice = 'No package.json with a "build" script found in this folder.';
        else foreach (run_frontend($dir, $fe, substr($action, 3)) as $l) $log[] = $l;
    }

    if ($action === 'storage_link') {
        $skipGit = true;
        if (!is_laravel($dir)) $notice = 'This folder is not a Laravel project.';
        else { [$ok, $m] = run_storage_link($dir); $log[] = ['php artisan storage:link', $ok, $m]; }
    }

    if (in_array($action, ['ht_public', 'ht_root'], true)) {
        $skipGit = true;
        if (!is_laravel($dir)) {
            $notice = 'This folder is not a Laravel project (artisan and public/index.php not found).';
        } elseif ($action === 'ht_public') {
            [$ok, $m] = ht_apply($dir . '/public/.htaccess', ht_block_public(), 'public');
            $log[] = ['public/.htaccess', $ok, $m];
        } else {
            [$ok, $m] = ht_apply($dir . '/.htaccess', ht_block_root(self_rel($dir)), 'root');
            $log[] = ['Root .htaccess', $ok, $m];
        }
    }

    if ($skipGit) {
    } elseif (!$GIT) {
        $notice = 'git was not found on this server (or exec is disabled).';
    } else {
        // URL: use the typed one, else the existing repo's origin
        $url = clean_url($f['url'], $emb);
        if (!$url && is_repo($dir)) {
            [, $o] = git(['remote', 'get-url', 'origin'], $dir);
            $url = clean_url($o, $emb2);
        }
        $cred = ['user' => $f['user'], 'pass' => $pass];
        if ($emb && $pass === '') $cred = $emb;
        if ($cred['pass'] === '') $cred = null;
        $target = is_dir($dir) ? $dir : dirname($dir);
        if (in_array($action, ['clone', 'pull'], true) && !@is_writable($target)) {
            $notice = "Folder is not writable by PHP: $target. Check the path, permissions, or open_basedir.";
            $action = '';
        }
        $branch = $f['branch'];
        $branchOk = $branch !== '' && preg_match('#^[A-Za-z0-9._/\-]+$#', $branch) && $branch[0] !== '-' && strpos($branch, '..') === false;

        if (!$url) {
            $notice = 'Enter a valid repository URL (https://..., ssh://... or git@host:...).';
        } elseif ($action === 'branches') {
            [$rc, $o] = git(['ls-remote', '--heads', '--', $url], null, $cred);
            if ($rc === 0) {
                $branches = parse_branches($o);
                $_SESSION['branches'] = $branches;
                $log[] = ['Remote branches', true, count($branches) . " branch(es) found:\n" . implode("\n", $branches)];
                if (!$f['branch'] || !in_array($f['branch'], $branches, true)) {
                    $f['branch'] = in_array('main', $branches, true) ? 'main' : (in_array('master', $branches, true) ? 'master' : ($branches[0] ?? ''));
                    $_SESSION['form'] = $f;
                }
            } else {
                $log[] = ['Could not list branches', false, $o];
            }
        } elseif (!$branchOk) {
            $notice = 'Choose a branch first (click "Load branches").';
        } elseif ($action === 'clone') {
            if (is_repo($dir)) {
                $notice = 'This folder is already a git repository. Use Pull / Update instead.';
            } elseif (!dir_only_self($dir) && empty($_POST['overwrite'])) {
                $notice = 'Target folder is not empty. Tick "Overwrite existing files" to check out into it anyway (tracked files will be replaced; other files are kept).';
            } else {
                if (!is_dir($dir) && !@mkdir($dir, 0755, true)) {
                    $log[] = ['Create folder', false, "Cannot create $dir"];
                } elseif (dir_empty($dir)) {
                    [$rc, $o] = git(['clone', '--branch', $branch, '--', $url, $dir], null, $cred);
                    $log[] = ['git clone', $rc === 0, $o];
                } else {
                    $steps = [
                        [['init'], null],
                        [['remote', 'add', 'origin', $url], null],
                        [['fetch', 'origin'], $cred],
                        [['checkout', '-f', '-B', $branch, 'origin/' . $branch], null],
                    ];
                    foreach ($steps as [$a, $c]) {
                        [$rc, $o] = git($a, $dir, $c);
                        $log[] = ['git ' . implode(' ', $a), $rc === 0, $o];
                        if ($rc !== 0) break;
                    }
                }
            }
        } elseif ($action === 'pull') {
            if (!is_repo($dir)) {
                $notice = 'Target folder is not a git repository yet. Use Clone / Checkout.';
            } else {
                $mode = ($_POST['mode'] ?? 'ff') === 'reset' ? 'reset' : 'ff';
                [, $before] = git(['rev-parse', '--short', 'HEAD'], $dir);
                [$rc, $o] = git(['remote', 'get-url', 'origin'], $dir);
                $cmds = [
                    [$rc === 0 ? ['remote', 'set-url', 'origin', $url] : ['remote', 'add', 'origin', $url], null],
                    [['fetch', 'origin', '--prune'], $cred],
                ];
                [$lrc] = git(['rev-parse', '--verify', '--quiet', 'refs/heads/' . $branch], $dir);
                $cmds[] = [$lrc === 0 ? ['checkout', $branch] : ['checkout', '-B', $branch, '--track', 'origin/' . $branch], null];
                $cmds[] = [$mode === 'reset' ? ['reset', '--hard', 'origin/' . $branch] : ['merge', '--ff-only', 'origin/' . $branch], null];
                $okAll = true;
                foreach ($cmds as [$a, $c]) {
                    [$rc, $o] = git($a, $dir, $c);
                    $log[] = ['git ' . implode(' ', $a), $rc === 0, $o];
                    if ($rc !== 0) { $okAll = false; break; }
                }
                [, $after] = git(['rev-parse', '--short', 'HEAD'], $dir);
                if ($okAll) $log[] = ['Result', true, $before === $after ? "Already up to date at $after" : "Updated $before -> $after"];
                elseif ($mode === 'ff') $log[] = ['Hint', false, 'If local changes or diverged history block the merge, use "Force reset to remote" (discards local changes).'];
            }
        }
    }
}

// optional: composer install, then migrations, after a successful clone/pull
if (isset($action) && in_array($action, ['clone', 'pull'], true) && $log) {
    $allOk = true;
    foreach ($log as $l) if (!$l[1]) $allOk = false;
    if ($allOk && !empty($_POST['composer_after']) && composer_info($dir)) {
        [$rc, $o] = run_composer($dir, !empty($_POST['with_dev']));
        $log[] = ['composer install' . (empty($_POST['with_dev']) ? ' --no-dev' : ''), $rc === 0, $o];
        $allOk = $rc === 0;
    }
    if ($allOk && !empty($_POST['frontend_after']) && ($fe = frontend_info($dir))) {
        foreach (run_frontend($dir, $fe, 'both') as $l) { $log[] = $l; if (!$l[1]) $allOk = false; }
    }
    if ($allOk && !empty($_POST['migrate_after']) && ($mi = migration_info($dir))) {
        if ($mi['vendor']) {
            [$rc, $o] = mig_exec($dir, $mi['run']);
            $log[] = [$mi['fw'] . ': php ' . implode(' ', $mi['run']), $rc === 0, $o];
        } else {
            $log[] = ['Migrations skipped', false, 'vendor/ is missing - run composer install first.'];
        }
    }
    if ($allOk && !empty($_POST['storage_after']) && is_laravel($dir)) {
        if (is_file($dir . '/vendor/autoload.php')) { [$ok, $m] = run_storage_link($dir); $log[] = ['php artisan storage:link', $ok, $m]; }
        else $log[] = ['storage:link skipped', false, 'vendor/ is missing - run composer install first.'];
    }
    if (!$allOk && (!empty($_POST['composer_after']) || !empty($_POST['migrate_after']) || !empty($_POST['storage_after']))) {
        $log[] = ['Later steps skipped', false, 'An earlier step failed.'];
    }
}

// ================= Current repo status =================
$dir = resolve_dir($f['dir']);
$info = null;
if ($GIT && is_repo($dir)) {
    $info = [];
    [, $info['branch']] = git(['rev-parse', '--abbrev-ref', 'HEAD'], $dir);
    [, $info['remote']] = git(['remote', 'get-url', 'origin'], $dir);
    [, $info['commit']] = git(['log', '-1', '--format=%h  %s  (%an, %ar)'], $dir);
    [, $st] = git(['status', '--porcelain'], $dir);
    $info['dirty'] = $st === '' ? 0 : count(explode("\n", $st));
    [, $lb] = git(['for-each-ref', '--format=%(refname:short)', 'refs/heads'], $dir);
    $info['local'] = $lb === '' ? [] : explode("\n", $lb);
    if ($f['url'] === '' && $info['remote']) { $emb3 = null; $f['url'] = clean_url($info['remote'], $emb3) ?: ''; }
    if ($f['branch'] === '') $f['branch'] = $info['branch'];
}

// ================= Render =================
page_head();
echo '<div class="top"><h1>GitDeploy</h1><a class="btn sec" href="?logout=1">Logout</a></div>';

if (password_verify('Admin@12345', ADMIN_PASSWORD_HASH)) echo '<div class="card er"><b>Default password in use.</b> Change ADMIN_PASSWORD_HASH at the top of this file before using it on a real server.</div>';
if (!$GIT) echo '<div class="card er">git was not found / exec is disabled on this server.</div>';
else echo '<p class="mut">git: ' . h($GIT) . ' &middot; PHP ' . h(PHP_VERSION) . '</p>';
if ($notice) echo '<div class="card er">' . h($notice) . '</div>';

$wr = @is_writable(is_dir($dir) ? $dir : dirname($dir));
echo '<div class="card"><h2>Repository status</h2><div class="kv"><b>Target folder</b><span>' . h($dir) . ' <span class="' . ($wr ? 'ok' : 'er') . '">(' . ($wr ? 'writable' : 'NOT writable') . ')</span></span>';
if ($info) {
    echo '<b>State</b><span class="ok">Existing git repository</span>'
       . '<b>Current branch</b><span><span class="tag">' . h($info['branch']) . '</span></span>'
       . '<b>Remote (origin)</b><span>' . h(mask($info['remote'], null)) . '</span>'
       . '<b>Last commit</b><span>' . h($info['commit']) . '</span>'
       . '<b>Local changes</b><span>' . ($info['dirty'] ? '<span class="er">' . (int)$info['dirty'] . ' modified/untracked file(s)</span>' : 'clean') . '</span>'
       . '<b>Local branches</b><span>' . h(implode(', ', $info['local'])) . '</span>';
} else {
    echo '<b>State</b><span>' . (is_dir($dir) && !dir_only_self($dir) ? 'Folder exists, not a git repo' : 'Empty / not created - ready to clone') . '</span>';
}
echo '</div></div>';

echo '<div class="card"><h2>Clone / Pull</h2><form method="post" autocomplete="off">'
   . '<input type="hidden" name="csrf" value="' . h($_SESSION['csrf']) . '">'
   . '<label>Repository URL</label><input type="text" name="url" value="' . h($f['url']) . '" placeholder="https://github.com/user/repo.git">'
   . '<div class="row"><div><label>Username</label><input type="text" name="user" value="' . h($f['user']) . '" placeholder="git username (any value for tokens on some hosts)"></div>'
   . '<div><label>Password / Access token</label><input type="password" name="pass" placeholder="' . ($saved && ($saved['pass'] ?? '') !== '' ? 'saved password will be used' : 'leave empty for public repos') . '" autocomplete="new-password"></div></div>'
   . '<label>Target folder (absolute path)</label><input type="text" name="dir" value="' . h($f['dir'] !== '' ? $f['dir'] : resolve_dir('')) . '" placeholder="/home/user/public_html">'
   . '<div class="mut">Editable. Type any absolute path (detected default: ' . h(default_dir()) . ')</div>'
   . '<label>Branch</label><select name="branch">';
$opts = $branches;
if ($f['branch'] !== '' && !in_array($f['branch'], $opts, true)) array_unshift($opts, $f['branch']);
if (!$opts) echo '<option value="">-- click "Load branches" --</option>';
foreach ($opts as $b) echo '<option value="' . h($b) . '"' . ($b === $f['branch'] ? ' selected' : '') . '>' . h($b) . '</option>';
echo '</select>'
   . '<label>Pull mode</label><select name="mode"><option value="ff">Fast-forward only (safe)</option><option value="reset">Force reset to remote (discards local changes)</option></select>'
   . '<div class="chk"><input type="checkbox" name="save" value="1" id="sv"' . ($saved ? ' checked' : '') . '><label for="sv" style="margin:0;color:inherit">Save these settings &amp; credentials on this server (optional, encrypted)</label></div>'
   . '<div class="chk"><input type="checkbox" name="overwrite" value="1" id="ow"><label for="ow" style="margin:0;color:inherit">Overwrite existing files (clone into a non-empty folder)</label></div>'
   . (composer_info($dir) ? '<div class="chk"><input type="checkbox" name="composer_after" value="1" id="cp"><label for="cp" style="margin:0;color:inherit">Run <code>composer install --no-dev</code> after clone / pull</label></div>'
       . '<div class="chk"><input type="checkbox" name="with_dev" value="1" id="wd"><label for="wd" style="margin:0;color:inherit">...include dev dependencies</label></div>' : '')
   . (($fb = frontend_info($dir)) ? '<div class="chk"><input type="checkbox" name="frontend_after" value="1" id="fe"><label for="fe" style="margin:0;color:inherit">Build frontend after clone / pull (<code>' . h($fb['pm']) . ' ' . ($fb['pm'] === 'npm' && $fb['lock'] ? 'ci' : 'install') . ' &amp;&amp; ' . h($fb['pm']) . ' run build</code>) - ' . h($fb['label']) . '</label></div>' : '')
   . (($mg = migration_info($dir)) ? '<div class="chk"><input type="checkbox" name="migrate_after" value="1" id="mg"><label for="mg" style="margin:0;color:inherit">Run ' . h($mg['fw']) . ' migrations after clone / pull (<code>' . h(implode(' ', $mg['run'])) . '</code>)</label></div>' : '')
   . (is_laravel($dir) ? '<div class="chk"><input type="checkbox" name="storage_after" value="1" id="sl"><label for="sl" style="margin:0;color:inherit">Run <code>php artisan storage:link</code> after clone / pull</label></div>' : '')
   . '<div class="actions">'
   . '<button class="sec" name="action" value="branches">1. Load branches</button>'
   . '<button name="action" value="clone"' . ($info ? ' class="sec"' : '') . '>2. Clone / Checkout</button>'
   . '<button name="action" value="pull"' . ($info ? '' : ' class="sec"') . '>2. Pull / Update</button>'
   . ($saved ? '<button class="sec" name="action" value="forget" formnovalidate>Forget saved credentials</button>' : '')
   . '</div></form></div>';

if ($ci = composer_info($dir)) {
    echo '<div class="card"><h2>Composer</h2><p class="mut">composer.json found'
       . ($ci['lock'] ? '' : ' <span class="er">(no composer.lock - versions will be resolved fresh)</span>')
       . ($ci['vendor'] ? ', vendor/ exists.' : ', <span class="er">vendor/ missing.</span>')
       . (find_composer($dir) ? '' : ' <span class="er">Composer binary not found.</span>') . '</p>'
       . '<form method="post"><input type="hidden" name="csrf" value="' . h($_SESSION['csrf']) . '">'
       . '<input type="hidden" name="dir" value="' . h($dir) . '">'
       . '<input type="hidden" name="url" value="' . h($f['url']) . '"><input type="hidden" name="user" value="' . h($f['user']) . '"><input type="hidden" name="branch" value="' . h($f['branch']) . '">'
       . '<div class="chk"><input type="checkbox" name="with_dev" value="1" id="wd2"><label for="wd2" style="margin:0;color:inherit">Include dev dependencies</label></div>'
       . '<div class="actions"><button name="action" value="composer">Run composer install</button></div></form></div>';
}

if ($mi = migration_info($dir)) {
    echo '<div class="card"><h2>Migrations</h2><p class="mut">' . h($mi['fw']) . ' project detected with ' . (int)$mi['count'] . ' migration file(s).'
       . (!$mi['vendor'] ? ' <span class="er">vendor/ is missing - run composer install first.</span>' : '')
       . (!$mi['env'] ? ' <span class="er">.env not found.</span>' : '') . '</p>'
       . '<form method="post"><input type="hidden" name="csrf" value="' . h($_SESSION['csrf']) . '">'
       . '<input type="hidden" name="dir" value="' . h($dir) . '">'
       . '<input type="hidden" name="url" value="' . h($f['url']) . '"><input type="hidden" name="user" value="' . h($f['user']) . '"><input type="hidden" name="branch" value="' . h($f['branch']) . '">'
       . '<div class="actions"><button class="sec" name="action" value="migstatus">Show migration status</button>'
       . '<button name="action" value="migrate" onclick="return confirm(\'Run migrations on this database now?\')">Run migrations</button></div></form></div>';
}

if ($fe = frontend_info($dir)) {
    $nt = find_node_tool($fe['pm']);
    echo '<div class="card"><h2>Frontend build</h2><p class="mut">' . h($fe['label']) . ' project detected (package manager: ' . h($fe['pm']) . ', build script: <code>' . h($fe['build']) . '</code>).'
       . ($nt ? '' : ' <span class="er">' . h($fe['pm']) . ' not found on this server - use cPanel "Setup Node.js App", or build locally and commit the built files.</span>') . '</p>'
       . '<form method="post"><input type="hidden" name="csrf" value="' . h($_SESSION['csrf']) . '">'
       . '<input type="hidden" name="dir" value="' . h($dir) . '">'
       . '<input type="hidden" name="url" value="' . h($f['url']) . '"><input type="hidden" name="user" value="' . h($f['user']) . '"><input type="hidden" name="branch" value="' . h($f['branch']) . '">'
       . '<div class="actions"><button class="sec" name="action" value="fe_install">' . h($fe['pm']) . ' install</button>'
       . '<button class="sec" name="action" value="fe_build">' . h($fe['pm']) . ' run build</button>'
       . '<button name="action" value="fe_both">Install + build</button></div></form></div>';
}

if (is_laravel($dir)) {
    [$sst, $sw] = storage_state($dir);
    echo '<div class="card"><h2>Storage link</h2><p class="' . ($sst === 'linked' ? 'ok' : 'er') . '" style="margin:0 0 6px">' . h($sw) . '</p>'
       . '<form method="post"><input type="hidden" name="csrf" value="' . h($_SESSION['csrf']) . '">'
       . '<input type="hidden" name="dir" value="' . h($dir) . '">'
       . '<input type="hidden" name="url" value="' . h($f['url']) . '"><input type="hidden" name="user" value="' . h($f['user']) . '"><input type="hidden" name="branch" value="' . h($f['branch']) . '">'
       . '<div class="actions"><button class="' . ($sst === 'linked' ? 'sec' : '') . '" name="action" value="storage_link">Run storage:link</button></div></form></div>';
}

if (is_laravel($dir)) {
    [$ps, $pw] = ht_state($dir . '/public/.htaccess', 'public');
    [$rs, $rw] = ht_state($dir . '/.htaccess', 'root');
    $inRoot = self_rel($dir) !== null && strpos(self_rel($dir), '/') === false;
    echo '<div class="card"><h2>Laravel .htaccess</h2><div class="kv">'
       . '<b>public/.htaccess</b><span class="' . ($ps === 'incomplete' || $ps === 'missing' ? 'er' : 'ok') . '">' . h($pw) . '</span>'
       . '<b>Root .htaccess</b><span class="' . ($rs === 'ok' || $rs === 'managed' ? 'ok' : 'mut') . '">' . h($rw) . '</span></div>'
       . '<p class="mut">' . ($inRoot
            ? 'This tool is in the project root, so the web root is probably the project folder: add the root rule so requests go to public/ (this tool stays reachable).'
            : 'If your document root is already set to public/, only public/.htaccess is needed; the root rule is for hosts where the web root is the project folder.')
       . ' Existing rules are kept and a backup is made before any change.</p>'
       . '<form method="post"><input type="hidden" name="csrf" value="' . h($_SESSION['csrf']) . '">'
       . '<input type="hidden" name="dir" value="' . h($dir) . '">'
       . '<input type="hidden" name="url" value="' . h($f['url']) . '"><input type="hidden" name="user" value="' . h($f['user']) . '"><input type="hidden" name="branch" value="' . h($f['branch']) . '">'
       . '<div class="actions"><button class="' . ($ps === 'ok' || $ps === 'managed' ? 'sec' : '') . '" name="action" value="ht_public">Add / check public/.htaccess</button>'
       . '<button class="' . ($inRoot ? '' : 'sec') . '" name="action" value="ht_root">Add / check root .htaccess</button></div></form></div>';
}

foreach ($log as [$title, $ok, $out]) {
    echo '<div class="card"><h2 class="' . ($ok ? 'ok' : 'er') . '">' . ($ok ? '&#10003; ' : '&#10007; ') . h($title) . '</h2>'
       . ($out !== '' ? '<pre>' . h($out) . '</pre>' : '<span class="mut">(no output)</span>') . '</div>';
}
page_foot();
