#ifndef STORE_H
#define STORE_H
#include <stdint.h>
#include "util.h"

#define MSG_MAX_BYTES 1000
#define HISTORY_LIMIT 50

/* Persistent message log (<datadir>/messages.log). `to` is "" for the group room. */
int  store_init(const char *datadir);
void store_shutdown(void);
int  store_add(const char *from, const char *to, const char *text, int64_t ts_ms);
/* Append a JSON array of the last `max` messages of one conversation.
   with == "" : group room. Otherwise: direct messages between `me` and `with`. */
void store_history_json(sb_t *out, const char *me, const char *with, int max);
#endif
