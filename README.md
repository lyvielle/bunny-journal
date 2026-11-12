> Disclaimer: Due to ongoing health issues I am no longer able to concentrate on developing software by myself. This project is therefore vibe-coded: written together with an AI assistant (Claude) and directed, tested and run by me. It is not a demo or proof of concept. It exists because I need it: it fixes a real problem in my day-to-day life and is in daily use. Read the code and the security notes below with that in mind.

# Bunny Journal

A self-hosted, single-user, password-encrypted Markdown diary. One Docker container (Flask + gunicorn), one encrypted file on a volume, and a single-page UI that is also an installable PWA. It is meant to run on a private network (for example a Tailscale tailnet) behind a reverse proxy that terminates TLS.

## Features

- **Encrypted at rest.** The first start asks for a password. It encrypts the whole journal (AES-256-GCM, key derived with scrypt).
- **Locks itself.** Close button, 10 minutes without activity, or a container restart.
- **Entries.** Any number of named entries, grouped by month. *Today* opens or creates the entry titled `YYYY-MM-DD`. Search covers all entries.
- **Text / MD modes.** Plain editor or rendered Markdown. The last choice is remembered per browser.
- **Writing aids.** Bookmarks, collapsible sections, outline from headings, task-list checkboxes, word count, autosave (800 ms after the last keystroke).
- **PDF export** of the open entry.
- **Safety net.** Backup download and restore, password change, snapshot history, stale-write detection between devices.
- **PWA.** Installable, with an offline fallback page. The service worker never caches journal data.

### Markdown extras

Standard Markdown (Python-Markdown with `extra`, `sane_lists`, `nl2br`; a single newline is a line break), plus:

| Syntax | Effect |
|---|---|
| `- [ ]` / `- [x]` | Task list. Ticking a box in MD mode edits the text. |
| `<!-- bm: Label -->` | Bookmark, listed in the side panel (added by the UI). |
| `<!-- fold: Title -->` … `<!-- /fold -->` | Collapsible section. Nestable; an unclosed section is closed at the end of the entry; stray closers are ignored. Exported expanded in the PDF. |

Raw HTML is sanitized (see [Security notes](#security-notes)). A line of `---` directly under a line of text turns that text into a heading (Markdown "setext" heading); leave a blank line before `---`.

## Architecture

```
browser (index.html, PWA)
   │  HTTPS
reverse proxy ── sets X-Forwarded-Proto / X-Forwarded-Host
   │  HTTP :8000
gunicorn  (1 worker, 4 threads)
   └─ Flask app (app.py)
        ├─ memory:  derived key, session tokens        ← lost on restart = locked
        └─ /data:   journal.enc, versions/, last_access.txt   (volume)
```

- **Backend** – one file, `app.py`: JSON API, crypto, sessions, Markdown → HTML (Python-Markdown, sanitized with bleach), PDF (WeasyPrint), PWA routes.
- **Frontend** – one file, `index.html`: inline CSS and JS, no framework, no build step, no external requests. All journal state lives on the server; the browser keeps only UI preferences in `localStorage` (`bj-mode`, `bj-entries`, `bj-panel`, `bj-entry`).
- **One worker on purpose.** The unlocked key lives in the memory of that process. A second worker would not share it, and a worker restart locks the journal.
- **No plaintext cache.** Each request that needs entries reads and decrypts `journal.enc` again. A global lock serializes access.
- **Whole-file writes.** Every save re-encrypts the whole journal into a temp file, fsyncs it and renames it over `journal.enc`.

## Authentication and encryption

**First start.** If `journal.enc` does not exist, the UI asks for a new password (at least 8 characters, entered twice) and creates an empty journal. Afterwards the same screen unlocks it. A wrong password gets `401` after a 1 s delay.

**Key derivation.** scrypt with N = 2^17, r = 8, p = 1 (about 128 MiB per derivation), 16-byte random salt, 32-byte key. The parameters are stored in the file header, so existing files keep working if the defaults change. Headers with log2(N) above 20 are rejected.

**File format `BJ2`** (`journal.enc`):

| Bytes | Content |
|---|---|
| 0–2 | magic `BJ2` |
| 3 / 4 / 5 | scrypt log2(N), r, p |
| 6–21 | salt |
| 22–33 | AES-GCM nonce (fresh random value on every write) |
| 34– | ciphertext + 16-byte tag of the UTF-8 JSON `{"entries":[{id, title, text, created, updated, rev}, …]}` |

Bytes 0–21 are authenticated as associated data. Entry ids are 8 random hex characters.

**Sessions.** A successful unlock issues a random token (`secrets.token_urlsafe(32)`) in the cookie `bj` (`HttpOnly`, `SameSite=Strict`, `Secure` when the request arrived over HTTPS according to `X-Forwarded-Proto`). The derived key exists once, in process memory, and is shared by all sessions, so several devices can be open at once.

**Auto-lock.**
- Every authenticated request refreshes that session's idle timer. An open page sends `/api/ping` every 60 s and again when it becomes visible.
- A session expires after 600 s without a request. A watchdog thread (every 15 s) drops expired sessions and discards the key when none remain.
- *Close* ends the calling session; if it was the last one, the key is discarded.
- A restart of the container or worker locks everything, because nothing but the encrypted file is persisted.

**Legacy format `BJ1`** (single document, scrypt N = 2^15) is migrated on first unlock into one entry titled "Journal". The original is kept as `journal.enc.bj1.bak`.

## Data directory

`DATA_DIR` (default `/data`):

| Path | Content |
|---|---|
| `journal.enc` | The encrypted journal. |
| `versions/<UTC timestamp>.enc` | Snapshots: copies of the previous `journal.enc`, at most one per 15 min, newest 20 kept. |
| `last_access.txt` | Plain-text UTC timestamp of the last successful unlock (shown as "Previously opened"). |
| `journal.enc.pre-restore` | The file that was replaced by the last restore. |
| `journal.enc.bj1.bak` | Pre-migration copy of a legacy `BJ1` file. |

## HTTP API

JSON over HTTP, session cookie `bj`. Endpoints marked *open* work without a session.

| Endpoint | Purpose |
|---|---|
| `GET /api/state` *(open)* | `{exists, unlocked}` |
| `POST /api/unlock` *(open)* | `{password}` → sets the cookie |
| `POST /api/lock` *(open)* | Ends the calling session |
| `POST /api/ping` | Keep-alive |
| `GET /api/entries` · `POST /api/entries` | List (without text) plus the previous access time · create `{title}` |
| `GET` · `PUT` · `DELETE /api/entries/<id>` | Read · update `{text, title}` · delete. `PUT` honors `If-Match: <rev>` and answers `409` with the server copy on a mismatch. |
| `GET /api/search?q=` | Case-insensitive substring search over titles and text, newest first, at most 50 results |
| `POST /api/render` · `POST /api/pdf` | Markdown → sanitized HTML · `{title, text}` → PDF (A4) |
| `GET /api/backup` · `POST /api/restore` | Raw `journal.enc` · replace it with the uploaded file (BJ2 or BJ1) and lock all sessions |
| `POST /api/password` | `{old, new}`: new salt, re-encrypts the journal and all snapshots |
| `GET /api/versions` · `POST /api/versions/restore` | List snapshots of the current key · restore one (the current state is snapshotted first) |
| `GET /`, `/offline`, `/manifest.webmanifest`, `/sw.js`, `/icons/<name>` *(open)* | UI and PWA assets |

## Deployment

```bash
git clone https://github.com/lyvielle/bunny-journal.git
cd bunny-journal
docker compose up -d --build
```

The container listens on port 8000 and stores data in the named volume `journal-data`. Put a reverse proxy in front:

- terminate TLS (service workers and PWA installation need HTTPS, except on `localhost`);
- send `X-Forwarded-Proto` and `X-Forwarded-Host` (the app trusts both through Werkzeug `ProxyFix`);
- allow request bodies up to 64 MiB (restore uploads; the app enforces the same limit).

Example for nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    client_max_body_size 64m;
}
```

By default `docker-compose.yml` publishes port 8000 on all host interfaces. If the proxy runs on the same host, set `BIND_ADDR=127.0.0.1` (see [Compose variables](#compose-variables)).

**Update:** `git pull && docker compose up -d --build`. The volume survives rebuilds; the update locks the journal because the container restarts.

**Backups:** use *Download backup* in the settings dialog (the file stays encrypted), or copy `journal.enc` out of the volume.

**Without Docker:** `pip install -r requirements.txt`, then `DATA_DIR=./data flask --app app run`. PDF export additionally needs Pango and a font such as DejaVu (see the `Dockerfile`).

## Configuration

Environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `DATA_DIR` | `/data` | Directory for the files listed under [Data directory](#data-directory). The image sets it to `/data` and declares it a volume. |

There are no other environment variables. The remaining settings are constants in `app.py` (or flags in the `Dockerfile`) and need a rebuild:

| Constant | Value | Meaning |
|---|---|---|
| `LOCK_AFTER` | `600` | Idle seconds before a session expires |
| `SNAP_EVERY` | `900` | Minimum seconds between snapshots |
| `KEEP` | `20` | Snapshots kept |
| `COST` | `(17, 8, 1)` | scrypt log2(N), r, p for new containers and password changes |
| `MAX_CONTENT_LENGTH` | 64 MiB | Maximum request body |
| gunicorn flags | `-w 1 --threads 4 -b 0.0.0.0:8000` | Keep a single worker |

### Compose variables

`docker-compose.yml` reads these from the shell or from a `.env` file next to it (`cp .env.example .env`). All are optional.

| Variable | Default | Meaning |
|---|---|---|
| `BIND_ADDR` | `0.0.0.0` | Host interface the port is published on. Use `127.0.0.1` behind a local reverse proxy. |
| `HOST_PORT` | `8000` | Host port mapped to container port 8000. |
| `DATA_DIR` | `/data` | Passed to the app as `DATA_DIR` and used as the mount point of the `journal-data` volume. |

The container port stays 8000 (set by the gunicorn flags in the `Dockerfile`). If you change `DATA_DIR`, also change the `VOLUME` line in the `Dockerfile`, otherwise Docker creates an extra anonymous volume for `/data`. Update the proxy target if you change `HOST_PORT`.

## Repository layout

```
.
├── app.py               Flask app: crypto, sessions, API, rendering, PWA routes
├── index.html           Single-page UI (inline CSS/JS)
├── icons/               PWA and favicon icons, served at /icons/<name>
├── Dockerfile           python:3.12-slim + Pango/fonts for PDF export, gunicorn
├── docker-compose.yml   Service + named volume journal-data (env-configurable)
├── .env.example         Compose variables
├── requirements.txt     flask, gunicorn, cryptography, markdown, bleach, weasyprint
├── .gitignore
└── README.md
```

## Security notes

The design protects the journal **at rest and in backups while it is locked**. It does not protect against someone who controls the running, unlocked container or the host.

- **Password is the only barrier.** The minimum is 8 characters and there is no other policy. Guessing is throttled by one scrypt derivation plus a 1 s delay per failed attempt, performed while holding the global lock. That is roughly one guess per 1.4 s for all clients together, but it also means anyone who can reach the server can keep it busy and delay legitimate requests. There is no per-client limit and no lockout. Keep the service on a private network or behind authentication at the proxy.
- **Key in memory while unlocked.** Locking drops the reference. Python does not zero memory and nothing prevents swapping, so swap files or core dumps on the host could contain the key or text.
- **Not encrypted:** file sizes and modification times, snapshot timestamps (in file names), `last_access.txt`, and the scrypt parameters and salt in the header (authenticated, not secret).
- **Unauthenticated endpoints** are listed in the API table. `/api/state` reveals whether a journal exists and whether the caller is unlocked.
- **CSRF** is handled by `SameSite=Strict` only; there are no CSRF tokens, and JSON bodies are parsed regardless of content type.
- **Sanitization.** Rendered Markdown goes through a bleach allowlist (links and images limited to `http`, `https`, `mailto`). Fold titles are inserted after sanitization and are HTML-escaped.
- **Remote images.** The CSP is `default-src 'self'` with inline script and style (single-file UI) and `img-src 'self' data: https:`. An entry that references a remote image makes your browser load it, which tells that host your IP address. PDF export is rendered on the server by WeasyPrint, which fetches such images itself. No `frame-ancestors` or `X-Frame-Options` header is set; HSTS is left to the proxy.
- **Proxy trust.** `ProxyFix` accepts `X-Forwarded-Proto` and `X-Forwarded-Host` from whoever connects. Do not expose port 8000 to untrusted networks directly.
- **Container.** It runs as root (no `USER` in the `Dockerfile`), and dependencies are not version-pinned.
- **Unlock field.** It is a masked text input (CSS `-webkit-text-security`, plus autofill-suppression attributes) so password managers do not offer to save it; where that CSS is unsupported it falls back to `type=password`. The trade-off is that it does not get the browser's built-in password-field handling.
- **Leftover files.** `journal.enc.bj1.bak` and `journal.enc.pre-restore` stay on the volume, encrypted under the password that was valid when they were written. A password change does **not** re-encrypt them (snapshots in `versions/` are re-encrypted). Delete them once you have checked the result. The same applies to backup files you downloaded earlier.
- **Restore** checks only the file header, not that the file can be decrypted. A valid-looking but unusable file replaces the journal; put `journal.enc.pre-restore` back to recover.

## Limitations

- Single user, single container, single worker. No sharing, no multi-user, no high availability.
- The journal is one encrypted blob that is read, decrypted and rewritten as a whole. Fine for a text diary, not for very large journals. There are no attachments; images work only as links.
- Snapshots are taken before a write, at most every 15 minutes, and the newest 20 are kept. A change can be up to 15 minutes newer than the snapshot you want to go back to, and snapshots are no substitute for off-site backups.
- Password change is not atomic across files: snapshots are re-encrypted first, the main file last. A crash in between leaves the journal under the old password and some snapshots unreadable. Files in `versions/` that cannot be decrypted with the current key are deleted during a password change.
- Stale-write detection covers edits of an entry only. Creating and deleting entries have no conflict check; the last writer wins.
- **An I/O error during any request** (for example a full disk) locks the journal and the API answers `401 locked`. The UI then returns to the lock screen and clears the editor, so text typed since the last successful save is lost.
- A browser that suspends the page (typical on mobile) stops the 60 s pings, so the session expires after 10 idle minutes and the next action shows the lock screen.
- Search is a plain substring match. The UI is English only. There is no automated test suite.
