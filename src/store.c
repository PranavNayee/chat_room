#define _POSIX_C_SOURCE 200809L
#include "store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define STORE_MAX 20000
#define STORE_DROP 2000

typedef struct {
    int64_t ts;
    char    from[USERNAME_MAX + 1];
    char    to[USERNAME_MAX + 1];
    char   *text;
} smsg_t;

static smsg_t *g_msgs;
static size_t  g_n, g_cap;
static int     g_fd = -1;

static int push(int64_t ts, const char *from, const char *to, const char *text)
{
    if (g_n >= STORE_MAX) {                  /* in-memory cap: forget the oldest batch */
        for (size_t i = 0; i < STORE_DROP; i++) free(g_msgs[i].text);
        memmove(g_msgs, g_msgs + STORE_DROP, (g_n - STORE_DROP) * sizeof *g_msgs);
        g_n -= STORE_DROP;
    }
    if (g_n == g_cap) {
        size_t nc = g_cap ? g_cap * 2 : 256;
        smsg_t *p = realloc(g_msgs, nc * sizeof *p);
        if (!p) return -1;
        g_msgs = p; g_cap = nc;
    }
    smsg_t *m = &g_msgs[g_n];
    m->text = strdup(text);
    if (!m->text) return -1;
    m->ts = ts;
    strncpy(m->from, from, USERNAME_MAX); m->from[USERNAME_MAX] = '\0';
    strncpy(m->to, to, USERNAME_MAX);     m->to[USERNAME_MAX] = '\0';
    g_n++;
    return 0;
}

int store_init(const char *datadir)
{
    char path[512];
    snprintf(path, sizeof path, "%s/messages.log", datadir);

    FILE *f = fopen(path, "r");
    if (f) {
        char *line = NULL; size_t cap = 0; ssize_t len;
        while ((len = getline(&line, &cap, f)) > 0) {
            line[strcspn(line, "\n")] = '\0';
            /* ts \t from \t to \t text */
            char *t1 = strchr(line, '\t'); if (!t1) continue; *t1++ = '\0';
            char *t2 = strchr(t1, '\t');   if (!t2) continue; *t2++ = '\0';
            char *t3 = strchr(t2, '\t');   if (!t3) continue; *t3++ = '\0';
            if (!valid_username(t1) || (t2[0] && !valid_username(t2))) continue;
            size_t tl = strlen(t3);
            if (tl == 0 || tl > MSG_MAX_BYTES || !utf8_valid(t3, tl)) continue;
            push((int64_t)strtoll(line, NULL, 10), t1, t2, t3);
        }
        free(line);
        fclose(f);
    }
    g_fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (g_fd < 0) { perror("open messages.log"); return -1; }
    fchmod(g_fd, 0600);
    return 0;
}

void store_shutdown(void)
{
    for (size_t i = 0; i < g_n; i++) free(g_msgs[i].text);
    free(g_msgs);
    g_msgs = NULL; g_n = g_cap = 0;
    if (g_fd >= 0) close(g_fd);
    g_fd = -1;
}

int store_add(const char *from, const char *to, const char *text, int64_t ts_ms)
{
    /* The text has already been validated to contain no control characters (so no tabs/newlines). */
    if (push(ts_ms, from, to, text) < 0) return -1;
    if (g_fd >= 0) {
        sb_t line; sb_init(&line);
        sb_printf(&line, "%lld\t%s\t%s\t%s\n", (long long)ts_ms, from, to, text);
        if (!line.oom) { ssize_t w = write(g_fd, line.data, line.len); (void)w; }
        sb_free(&line);
    }
    return 0;
}

static int in_conversation(const smsg_t *m, const char *me, const char *with)
{
    if (with[0] == '\0') return m->to[0] == '\0';
    return (strcmp(m->from, me) == 0 && strcmp(m->to, with) == 0) ||
           (strcmp(m->from, with) == 0 && strcmp(m->to, me) == 0);
}

void store_history_json(sb_t *out, const char *me, const char *with, int max)
{
    size_t idx[HISTORY_LIMIT];
    int found = 0;
    if (max > HISTORY_LIMIT) max = HISTORY_LIMIT;
    for (size_t i = g_n; i > 0 && found < max; i--)
        if (in_conversation(&g_msgs[i - 1], me, with)) idx[found++] = i - 1;

    sb_putc(out, '[');
    for (int k = found - 1; k >= 0; k--) {
        const smsg_t *m = &g_msgs[idx[k]];
        if (k != found - 1) sb_putc(out, ',');
        sb_puts(out, "{\"from\":");  sb_json_str(out, m->from);
        sb_puts(out, ",\"to\":");    sb_json_str(out, m->to);
        sb_puts(out, ",\"text\":");  sb_json_str(out, m->text);
        sb_printf(out, ",\"ts\":%lld}", (long long)m->ts);
    }
    sb_putc(out, ']');
}
