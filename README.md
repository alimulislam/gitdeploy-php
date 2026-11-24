# GitDeploy

A **single-file PHP tool** for cPanel / shared hosting that clones and updates a git repository from the browser.
Drop `gitdeploy.php` on the server, log in, enter your repo URL and credentials, pick a branch, and click **Clone** or **Pull**. No SSH, no Composer, no dependencies.

It also detects what kind of project you deployed and offers the usual post-deploy steps (Composer, npm build, migrations, `storage:link`, Laravel `.htaccess`) only when they apply.

> **Security first:** the file ships with a **test password** (`Admin@12345`). Change it before putting the file on a real server, and delete the file when you are finished. See [Security](#security).

## Features

- **Clone or pull** any HTTPS git repository (GitHub, Bitbucket, GitLab, Azure DevOps, Gitea, self-hosted)
- **Branch picker** - "Load branches" lists remote branches; choose which to check out or pull
- **Repository status** - current branch, remote, last commit, local changes, local branches, writable check
- **Safe pull** (fast-forward only) or **force reset** to the remote (discards local changes)
- **Existing project?** Checks out into a non-empty folder (with an explicit "Overwrite" confirmation)
- **Credentials never touch `.git/config` or the process list** (passed through an askpass helper); output is masked
- **Optional saved credentials** - AES-256-GCM encrypted file, stored above the web root when possible; one click to forget
- **Smart target folder** - finds an existing repo above the script, or the project root when the script lives in Laravel's `public/`
- **Login protection** - password hash, CSRF tokens, per-IP lockout, optional IP allow-list

### Post-deploy tools (shown only when relevant)

| Tool | Appears when | Runs |
|---|---|---|
| **Composer** | `composer.json` exists | `composer install --no-dev --optimize-autoloader` (dev deps optional) |
| **Frontend build** | `package.json` has a `build` script (Vue, React, Next, Nuxt, Svelte, Angular, Vite, Laravel + Vue/React) | `npm ci`/`install` + `npm run build` (yarn and pnpm detected from lock files) |
| **Migrations** | Laravel, CodeIgniter 4, Symfony (Doctrine), Yii 2, CakePHP or Phinx with migration files | The framework's own migrate command |
| **Storage link** | Laravel | `php artisan storage:link` (with a symlink fallback) |
| **Laravel `.htaccess`** | Laravel | Adds/checks `public/.htaccess` and a root `.htaccess` that routes to `public/` and keeps `gitdeploy.php` reachable |

Each can also be ticked as **"run after clone / pull"**. Order: Composer, frontend build, migrations, storage link. A failed step stops the rest.

## Requirements

- PHP 7.4+ (tested on 8.x) with `proc_open` enabled
- `git` on the server (cPanel's `/usr/local/cpanel/3rdparty/bin/git` is found automatically)
- `openssl` extension only if you use saved credentials
- Optional, for the post-deploy tools: PHP CLI, Composer, Node.js

## Install

1. Upload `gitdeploy.php` to your site, for example `public_html/gitdeploy.php`.
2. **Change the password** (see below).
3. Open `https://your-domain.com/gitdeploy.php` and log in.

### Change the password

Generate a hash locally:

```bash
php -r 'echo password_hash("YourNewStrongPassword", PASSWORD_DEFAULT);'
```

Paste it into the top of `gitdeploy.php`:

```php
const ADMIN_PASSWORD_HASH = '$2y$10$...your hash...';
```

While the default password is still in use, the page shows a red warning.

### Other settings (top of the file)

```php
const DEFAULT_TARGET_DIR = '';      // fixed repo folder; empty = auto-detect
const ALLOWED_IPS = [];             // e.g. ['203.0.113.10'] to restrict access
const MAX_LOGIN_FAILS = 5;          // lock out after N failed logins...
const LOCKOUT_SECONDS = 900;        // ...for this many seconds, per IP
```

## Usage

1. **Repository URL** - e.g. `https://github.com/you/project.git`
2. **Username / token** - see the table below. Leave blank for public repos.
3. **Target folder** - editable; defaults to the detected project root.
4. Click **Load branches**, choose a branch.
5. Click **Clone / Checkout** (new) or **Pull / Update** (existing repo).
6. Tick the "after clone / pull" boxes you want, or use each tool's card.

### Credentials by platform

| Platform | Username | Password field |
|---|---|---|
| GitHub | your username | Personal Access Token (`repo` / Contents: read) |
| Bitbucket Cloud | your username | App Password (Repositories: read); for access tokens use `x-token-auth` |
| GitLab | your username or `oauth2` | Token with `read_repository` |
| Azure DevOps, Gitea, self-hosted | your username | Token or password |

SSH URLs (`git@host:org/repo.git`) are accepted but only work if the server already has an authorised SSH key; HTTPS is recommended on shared hosting.

### Laravel notes

- If the document root is already `public/`, put `gitdeploy.php` inside `public/`; the target folder is detected as the project root one level up.
- If the web root is the project folder, use **Add / check root .htaccess** so requests route to `public/` while the tool stays reachable.
- Existing `.htaccess` content is never overwritten: a backup is created and a clearly marked block (`# BEGIN GitDeploy Laravel` ... `# END`) is added or updated.

## Security

This tool can write files and run commands on your server. Treat it accordingly.

- **Change the default password** and use a strong one.
- **Delete `gitdeploy.php` when you are done**, or restrict it with `ALLOWED_IPS` / HTTP basic auth / a hard-to-guess filename.
- Use **HTTPS** only; the session cookie is `HttpOnly` and `SameSite=Strict`.
- Use **least-privilege tokens** (read-only repository access).
- Credentials are not stored unless you tick **Save**; saved data is encrypted with a key derived from the password hash, so changing the hash invalidates it (save again).
- The deployment folder must be writable by the PHP user. Shared hosts with `open_basedir` may block folders above the web root.

## Limitations

- Needs `proc_open`/`exec`; some hosts disable them.
- Long operations (Composer, npm builds) can be cut off by host time or memory limits; run them over SSH or in CI if so.
- Migration detection looks only at default migration folders.
- Subfolder installs (`example.com/app/`) need a manual `RewriteBase` for the root `.htaccess` rules.

## Troubleshooting

| Message | Likely cause |
|---|---|
| `git was not found` | git missing or `exec` disabled - ask the host |
| `Folder is not writable by PHP` | wrong path, permissions, or `open_basedir` |
| `Authentication failed` | wrong token / scope; check username rules above |
| `Not possible to fast-forward` | local changes or diverged history - use **Force reset** |
| `vendor/ is missing` | run Composer first |
| `Composer not found` / `npm not found` | upload `composer.phar` to your home folder / use cPanel "Setup Node.js App" |

## License

MIT - see [LICENSE](LICENSE).
