# Secure Multi-User Chat (C + WebSocket)

A real-time chat server written in C11 with no external dependencies, plus a browser frontend.
One program serves the web page, the JSON API and the WebSocket endpoint.

**Features**

- Accounts: sign up / log in / log out (passwords hashed with PBKDF2-HMAC-SHA256, per-user salt)
- **Group chat** (`# General`) and **personal (1-to-1) chat** with any registered user, online or offline
- Message history for the group and for each private conversation (persisted across restarts)
- Online/offline presence, typing indicators, multi-tab / multi-device per account
- Responsive dark UI

## Build and run

```bash
make                 # release build  -> ./chat_server
./chat_server        # http://127.0.0.1:8080
```

Open the URL in two browsers (or one normal + one private window), sign up as two different users,
and click the other user in the sidebar to start a private chat.

```
Options:
  -p PORT        listen port (default 8080)
  -b ADDR        bind address (default 127.0.0.1 - localhost only)
  -d DIR         data directory (default ./data)
  -w DIR         web root (default ./public)
  --secure       Secure cookies + HSTS (use when served over HTTPS via a proxy)
  --trust-proxy  take client IP from X-Forwarded-For (only behind a proxy you control)
```

Other targets: `make debug` (AddressSanitizer + UBSan), `make test` (unit + end-to-end tests,
needs `python3`), `make clean`.

## Security model

| Area | What is done |
|---|---|
| Passwords | PBKDF2-HMAC-SHA256, 100,000 iterations, 16-byte random salt per user, constant-time compare. Iteration count is stored per user so it can be raised later. Min 8 / max 128 chars, common-password blocklist. Unknown usernames burn the same CPU time, so response timing doesn't reveal which accounts exist. |
| Sessions | 256-bit random token from `/dev/urandom` in an `HttpOnly; SameSite=Strict` cookie (`Secure` with `--secure`). Only the SHA-256 of the token is kept server-side. 24h expiry. New token on every login (no fixation). Logout destroys the session **and closes its live WebSockets**; expiry is also enforced on open sockets. |
| Identity | The sender of every message is taken from the authenticated session, never from the message body. |
| Brute force | Login: 5 failures/5 min per account, 20 failures/10 min per IP -> HTTP 429. Registration: 10/hour per IP. Per-connection token-bucket message rate limit; persistent flooders are disconnected. |
| CSRF / CSWSH | WebSocket and POST endpoints verify the `Origin` header matches `Host`; JSON-only content type; SameSite=Strict cookie. |
| Injection / XSS | Strict JSON parser (rejects duplicate keys, trailing data, NULs, bad surrogates, depth bombs); all output JSON-escaped; frontend only uses `textContent` (never `innerHTML`); CSP `default-src 'none'; script-src 'self'`; control characters and invalid UTF-8 rejected. |
| HTTP hardening | Static files are an explicit allow-list (URL never becomes a file path -> no traversal); rejects `Transfer-Encoding`, duplicate `Content-Length`, bare CR/LF, oversized headers/bodies; `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `no-store`. |
| WebSocket | RFC 6455: client frames must be masked, RSV bits and opcodes validated, 8 KB max message, fragmentation reassembly, ping/pong keepalive, idle/half-open connection cleanup. |
| Resource limits | 512 connections, 20 per IP, 8 per user, 1 MB write-buffer cap (slow consumers dropped), 10 s timeout for incomplete HTTP requests. |
| Files | Data dir `0700`, `users.db` / `messages.log` `0600`. Binds to `127.0.0.1` by default. |

### Things you must still do for real deployments

1. **Use TLS.** The C server speaks plain HTTP. Put nginx/Caddy in front, terminate HTTPS there,
   proxy `/` including WebSocket upgrades, and start with `--secure --trust-proxy`.
   Without TLS, passwords and messages are readable on the network. The server prints a warning
   when bound beyond localhost without `--secure`.
2. Messages are stored **unencrypted** on the server (`data/messages.log`). This is server-side
   chat, not end-to-end encryption - the server operator can read private messages.
3. Sessions are in memory, so everyone is logged out when the server restarts.
4. Hashing runs on the single event-loop thread (~50 ms per login). The per-IP/per-account
   throttles bound abuse; for a large public service, move hashing to worker threads.
5. No password reset / e-mail verification (there is no e-mail). Back up `data/users.db`.
6. `messages.log` grows forever; the server keeps the newest 20,000 messages in memory.

## Protocol

`POST /api/register`, `POST /api/login` with `{"username","password"}` set the session cookie.
`POST /api/logout`, `GET /api/me`. Then `GET /ws` (WebSocket, cookie required).

Client -> server (JSON text frames)

```
{"type":"msg","to":"","text":"hi all"}          group message  (to = "" or omitted)
{"type":"msg","to":"bob","text":"hi bob"}       private message
{"type":"history","with":""|"bob"}              last 50 messages of a conversation
{"type":"typing","to":""|"bob"}
{"type":"users"}
```

Server -> client: `hello`, `users`, `presence`, `msg`, `history`, `typing`, `error`.

## Layout

```
Makefile  README.md
src/   main.c server.c(poll loop, sockets, WS framing glue) chat.c(group/DM logic)
       http.c(parser, router, auth API) ws.c json.c auth.c(users, sessions) store.c(messages)
       ratelimit.c util.c sha1.c sha256.c base64.c
public/ index.html app.js style.css
tests/  unit_tests.c (RFC vectors for SHA/HMAC/PBKDF2/WebSocket, JSON, framing)
        e2e_test.py  (69 end-to-end checks incl. auth, DMs, abuse cases)
data/   created at runtime: users.db, messages.log
```
