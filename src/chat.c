#include "chat.h"
#include "auth.h"
#include "json.h"
#include "store.h"
#include "util.h"
#include <string.h>

static void send_sb(client_t *c, sb_t *b)
{
    if (!b->oom) srv_send_text(c, b->data, b->len);
    sb_free(b);
}

static void send_error(client_t *c, const char *msg)
{
    sb_t b; sb_init(&b);
    sb_puts(&b, "{\"type\":\"error\",\"message\":"); sb_json_str(&b, msg); sb_putc(&b, '}');
    send_sb(c, &b);
}

static void send_users(client_t *c)
{
    sb_t b; sb_init(&b);
    sb_puts(&b, "{\"type\":\"users\",\"users\":[");
    for (size_t i = 0; i < auth_user_count(); i++) {
        const char *n = auth_user_at(i);
        if (i) sb_putc(&b, ',');
        sb_puts(&b, "{\"name\":"); sb_json_str(&b, n);
        sb_printf(&b, ",\"online\":%s}", srv_user_conn_count(n) > 0 ? "true" : "false");
    }
    sb_puts(&b, "]}");
    send_sb(c, &b);
}

static void send_history(client_t *c, const char *me, const char *with)
{
    sb_t b; sb_init(&b);
    sb_puts(&b, "{\"type\":\"history\",\"with\":"); sb_json_str(&b, with);
    sb_puts(&b, ",\"messages\":");
    store_history_json(&b, me, with, HISTORY_LIMIT);
    sb_putc(&b, '}');
    send_sb(c, &b);
}

static void presence(const char *user, int online)
{
    sb_t b; sb_init(&b);
    sb_puts(&b, "{\"type\":\"presence\",\"name\":"); sb_json_str(&b, user);
    sb_printf(&b, ",\"online\":%s}", online ? "true" : "false");
    if (!b.oom) srv_broadcast(b.data, b.len, NULL);
    sb_free(&b);
}

void chat_on_connect(client_t *c, const char *user)
{
    sb_t b; sb_init(&b);
    sb_puts(&b, "{\"type\":\"hello\",\"user\":"); sb_json_str(&b, user); sb_putc(&b, '}');
    send_sb(c, &b);
    send_users(c);
    send_history(c, user, "");
    if (srv_user_conn_count(user) == 1) presence(user, 1);
}

void chat_on_disconnect(const char *user)
{
    if (srv_user_conn_count(user) == 0) presence(user, 0);
}

void chat_on_register(const char *user) { presence(user, 0); }

void chat_on_text(client_t *c, const char *user, const char *text, size_t len)
{
    char type[16], to[64], with[64], body[MSG_MAX_BYTES + 1];
    json_field_t f[4] = {
        { "type", type, sizeof type, 0 }, { "to", to, sizeof to, 0 },
        { "with", with, sizeof with, 0 }, { "text", body, sizeof body, 0 },
    };
    int r = json_parse_fields(text, len, f, 4);
    if (r == JSON_TOO_LONG) { send_error(c, "Message too long (max 1000 bytes)"); return; }
    if (r != JSON_OK || !f[0].found) { send_error(c, "Malformed message"); return; }

    /* Identity always comes from the authenticated session, never from the payload. */
    if (!strcmp(type, "msg")) {
        if (!f[3].found) { send_error(c, "Missing text"); return; }
        size_t bl = strlen(body);
        if (has_control_chars(body, bl)) { send_error(c, "Message contains control characters"); return; }
        char *t = str_trim(body);
        if (!*t) return;                                   /* blank: ignore */

        const char *target = "";
        if (f[1].found && to[0]) {
            target = auth_canonical(to);
            if (!target) { send_error(c, "No such user"); return; }
            if (!strcmp(target, user)) { send_error(c, "You can't message yourself"); return; }
        }
        int64_t ts = wall_ms();
        if (store_add(user, target, t, ts) < 0) { send_error(c, "Could not store message"); return; }

        sb_t b; sb_init(&b);
        sb_puts(&b, "{\"type\":\"msg\",\"from\":"); sb_json_str(&b, user);
        sb_puts(&b, ",\"to\":"); sb_json_str(&b, target);
        sb_puts(&b, ",\"text\":"); sb_json_str(&b, t);
        sb_printf(&b, ",\"ts\":%lld}", (long long)ts);
        if (!b.oom) {
            if (!target[0]) srv_broadcast(b.data, b.len, NULL);
            else { srv_send_user(target, b.data, b.len); srv_send_user(user, b.data, b.len); }
        }
        sb_free(&b);
    } else if (!strcmp(type, "history")) {
        const char *w = "";
        if (f[2].found && with[0]) {
            w = auth_canonical(with);
            if (!w || !strcmp(w, user)) { send_error(c, "No such user"); return; }
        }
        send_history(c, user, w);
    } else if (!strcmp(type, "typing")) {
        sb_t b; sb_init(&b);
        const char *target = "";
        if (f[1].found && to[0]) {
            target = auth_canonical(to);
            if (!target || !strcmp(target, user)) { sb_free(&b); return; }
        }
        sb_puts(&b, "{\"type\":\"typing\",\"from\":"); sb_json_str(&b, user);
        sb_puts(&b, ",\"to\":"); sb_json_str(&b, target); sb_putc(&b, '}');
        if (!b.oom) {
            if (!target[0]) srv_broadcast(b.data, b.len, user);
            else srv_send_user(target, b.data, b.len);
        }
        sb_free(&b);
    } else if (!strcmp(type, "users")) {
        send_users(c);
    } else {
        send_error(c, "Unknown message type");
    }
}
