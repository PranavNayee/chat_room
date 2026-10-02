#define _POSIX_C_SOURCE 200809L
#include "auth.h"
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define MAX_SESSIONS 2048
#define SALT_LEN 16
#define HASH_LEN 32

typedef struct {
    char     name[USERNAME_MAX + 1];
    uint8_t  salt[SALT_LEN];
    uint8_t  hash[HASH_LEN];
    uint32_t iters;
} user_t;

typedef struct {
    uint8_t token_hash[SESSION_HASH_LEN];
    char    user[USERNAME_MAX + 1];
    int64_t expires;
    int     used;
} session_t;

static user_t    g_users[MAX_USERS];
static size_t    g_nusers;
static session_t g_sessions[MAX_SESSIONS];
static int       g_dbfd = -1;

static int find_user(const char *name)
{
    for (size_t i = 0; i < g_nusers; i++)
        if (strcasecmp(g_users[i].name, name) == 0) return (int)i;
    return -1;
}

int auth_init(const char *datadir)
{
    char path[512];
    snprintf(path, sizeof path, "%s/users.db", datadir);

    FILE *f = fopen(path, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof line, f)) {
            /* name:iters:salt_hex:hash_hex */
            line[strcspn(line, "\r\n")] = '\0';
            char *parts[4]; int np = 0;
            char *p = line;
            while (np < 4) { parts[np++] = p; char *c = strchr(p, ':'); if (!c) break; *c = '\0'; p = c + 1; }
            if (np != 4 || !valid_username(parts[0])) { fprintf(stderr, "users.db: skipping malformed line\n"); continue; }
            if (g_nusers >= MAX_USERS) break;
            user_t *u = &g_users[g_nusers];
            char *end;
            long it = strtol(parts[1], &end, 10);
            if (*end || it < 1000 || it > 10000000) continue;
            if (hex_decode(parts[2], u->salt, SALT_LEN) < 0 || hex_decode(parts[3], u->hash, HASH_LEN) < 0) continue;
            strncpy(u->name, parts[0], USERNAME_MAX);
            u->name[USERNAME_MAX] = '\0';
            u->iters = (uint32_t)it;
            g_nusers++;
        }
        fclose(f);
    }
    g_dbfd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (g_dbfd < 0) { perror("open users.db"); return -1; }
    fchmod(g_dbfd, 0600);
    return 0;
}

void auth_shutdown(void)
{
    if (g_dbfd >= 0) close(g_dbfd);
    g_dbfd = -1;
    secure_zero(g_users, sizeof g_users);
    secure_zero(g_sessions, sizeof g_sessions);
    g_nusers = 0;
}

const char *auth_password_problem(const char *name, const char *pw)
{
    static const char *common[] = { "password", "12345678", "123456789", "1234567890", "qwertyui",
        "qwerty123", "iloveyou", "password1", "11111111", "abcd1234", "letmein1", NULL };
    size_t n = strlen(pw);
    if (n < PASSWORD_MIN) return "Password must be at least 8 characters";
    if (n > PASSWORD_MAX) return "Password must be at most 128 characters";
    if (name && strcasecmp(name, pw) == 0) return "Password must not match the username";
    for (int i = 0; common[i]; i++)
        if (strcasecmp(pw, common[i]) == 0) return "Password is too common";
    return NULL;
}

int auth_register(const char *name, const char *password)
{
    if (!valid_username(name)) return AUTH_BAD_NAME;
    if (auth_password_problem(name, password)) return AUTH_WEAK_PW;
    if (find_user(name) >= 0) return AUTH_EXISTS;
    if (g_nusers >= MAX_USERS) return AUTH_FULL;
    if (g_dbfd < 0) return AUTH_INTERNAL;

    user_t u;
    memset(&u, 0, sizeof u);
    strncpy(u.name, name, USERNAME_MAX);
    u.iters = PBKDF2_ITERS;
    if (rand_bytes(u.salt, SALT_LEN) < 0) return AUTH_INTERNAL;
    pbkdf2_sha256((const uint8_t *)password, strlen(password), u.salt, SALT_LEN, u.iters, u.hash, HASH_LEN);

    char saltx[SALT_LEN * 2 + 1], hashx[HASH_LEN * 2 + 1], line[256];
    hex_encode(u.salt, SALT_LEN, saltx);
    hex_encode(u.hash, HASH_LEN, hashx);
    int n = snprintf(line, sizeof line, "%s:%u:%s:%s\n", u.name, u.iters, saltx, hashx);
    if (n <= 0 || write(g_dbfd, line, (size_t)n) != n) return AUTH_INTERNAL;
    fsync(g_dbfd);

    g_users[g_nusers++] = u;
    secure_zero(&u, sizeof u);
    return AUTH_OK;
}

int auth_verify(const char *name, const char *password, char canon[USERNAME_MAX + 1])
{
    static const uint8_t dummy_salt[SALT_LEN] = { 'd','u','m','m','y','s','a','l','t',0,1,2,3,4,5,6 };
    uint8_t derived[HASH_LEN];
    int idx = find_user(name);

    if (idx < 0) {
        /* Burn the same CPU time so response timing doesn't reveal whether a name exists. */
        pbkdf2_sha256((const uint8_t *)password, strlen(password), dummy_salt, SALT_LEN, PBKDF2_ITERS, derived, HASH_LEN);
        secure_zero(derived, sizeof derived);
        return 0;
    }
    user_t *u = &g_users[idx];
    pbkdf2_sha256((const uint8_t *)password, strlen(password), u->salt, SALT_LEN, u->iters, derived, HASH_LEN);
    int ok = ct_equal(derived, u->hash, HASH_LEN);
    secure_zero(derived, sizeof derived);
    if (ok) { strncpy(canon, u->name, USERNAME_MAX); canon[USERNAME_MAX] = '\0'; }
    return ok;
}

const char *auth_canonical(const char *name)
{
    int i = find_user(name);
    return i < 0 ? NULL : g_users[i].name;
}

size_t auth_user_count(void) { return g_nusers; }
const char *auth_user_at(size_t i) { return i < g_nusers ? g_users[i].name : NULL; }

/* ---------- sessions ---------- */

int auth_session_create(const char *user, char token_out[TOKEN_HEX_LEN + 1])
{
    uint8_t raw[32];
    if (rand_bytes(raw, sizeof raw) < 0) return -1;
    hex_encode(raw, sizeof raw, token_out);

    int64_t now = mono_ms();
    int slot = -1, oldest = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].used || g_sessions[i].expires <= now) { slot = i; break; }
        if (g_sessions[i].expires < g_sessions[oldest].expires) oldest = i;
    }
    if (slot < 0) slot = oldest; /* table full of live sessions: evict the one closest to expiry */

    session_t *s = &g_sessions[slot];
    memset(s, 0, sizeof *s);
    sha256(token_out, TOKEN_HEX_LEN, s->token_hash);
    strncpy(s->user, user, USERNAME_MAX);
    s->expires = now + SESSION_TTL_MS;
    s->used = 1;
    secure_zero(raw, sizeof raw);
    return 0;
}

static session_t *session_by_hash(const uint8_t h[SESSION_HASH_LEN])
{
    int64_t now = mono_ms();
    session_t *found = NULL;
    for (int i = 0; i < MAX_SESSIONS; i++) {         /* no early exit: keep timing independent of position */
        session_t *s = &g_sessions[i];
        if (s->used && s->expires > now && ct_equal(s->token_hash, h, SESSION_HASH_LEN)) found = s;
    }
    return found;
}

const char *auth_session_lookup(const char *token, uint8_t sess_hash[SESSION_HASH_LEN])
{
    if (!token || strlen(token) != TOKEN_HEX_LEN) return NULL;
    for (int i = 0; i < TOKEN_HEX_LEN; i++) {
        char c = token[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return NULL;
    }
    uint8_t h[SESSION_HASH_LEN];
    sha256(token, TOKEN_HEX_LEN, h);
    session_t *s = session_by_hash(h);
    if (!s) return NULL;
    if (sess_hash) memcpy(sess_hash, h, SESSION_HASH_LEN);
    return s->user;
}

int auth_session_valid(const uint8_t h[SESSION_HASH_LEN]) { return session_by_hash(h) != NULL; }

void auth_session_destroy(const char *token)
{
    if (!token || strlen(token) != TOKEN_HEX_LEN) return;
    uint8_t h[SESSION_HASH_LEN];
    sha256(token, TOKEN_HEX_LEN, h);
    session_t *s = session_by_hash(h);
    if (s) secure_zero(s, sizeof *s);
}
