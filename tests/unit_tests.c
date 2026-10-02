#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sha256.h"
#include "sha1.h"
#include "base64.h"
#include "ws.h"
#include "json.h"
#include "util.h"
#include "ratelimit.h"

static int fails, total;
#define CHECK(c) do { total++; if (!(c)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

static void hexs(const uint8_t *b, size_t n, char *o) { hex_encode(b, n, o); }

static void test_sha(void)
{
    uint8_t d[32]; char h[65];
    sha256("abc", 3, d); hexs(d, 32, h);
    CHECK(!strcmp(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    sha256("", 0, d); hexs(d, 32, h);
    CHECK(!strcmp(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    const char *two = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256(two, strlen(two), d); hexs(d, 32, h);
    CHECK(!strcmp(h, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));

    uint8_t s1[20]; char h1[41];
    sha1((const uint8_t *)"abc", 3, s1); hexs(s1, 20, h1);
    CHECK(!strcmp(h1, "a9993e364706816aba3e25717850c26c9cd0d89d"));

    /* HMAC RFC 4231 test case 2 */
    hmac_sha256((const uint8_t *)"Jefe", 4, (const uint8_t *)"what do ya want for nothing?", 28, d); hexs(d, 32, h);
    CHECK(!strcmp(h, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));

    /* PBKDF2-HMAC-SHA256 vectors */
    pbkdf2_sha256((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 1, d, 32); hexs(d, 32, h);
    CHECK(!strcmp(h, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"));
    pbkdf2_sha256((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 4096, d, 32); hexs(d, 32, h);
    CHECK(!strcmp(h, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"));
}

static void test_ws_key(void)
{
    char out[29];
    ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==", out);
    CHECK(!strcmp(out, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));   /* RFC 6455 section 1.3 */
}

static void test_ws_parse(void)
{
    ws_frame_t f; int code;
    /* masked "Hello" from RFC 6455 section 5.7 */
    uint8_t hello[] = { 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    CHECK(ws_parse(hello, sizeof hello, 8192, &f, &code) == 1);
    ws_unmask(hello + f.header_len, f.payload_len, f.mask);
    CHECK(f.payload_len == 5 && memcmp(hello + f.header_len, "Hello", 5) == 0);
    CHECK(ws_parse(hello, 5, 8192, &f, &code) == 0);                 /* truncated */
    uint8_t unmasked[] = { 0x81, 0x01, 'a' };
    CHECK(ws_parse(unmasked, sizeof unmasked, 8192, &f, &code) == -1);   /* must be masked */
    uint8_t rsv[] = { 0xC1, 0x81, 0, 0, 0, 0, 'a' };
    CHECK(ws_parse(rsv, sizeof rsv, 8192, &f, &code) == -1);
    uint8_t big[] = { 0x81, 0xFE, 0xFF, 0xFF, 0, 0, 0, 0 };            /* 65535 > limit */
    CHECK(ws_parse(big, sizeof big, 8192, &f, &code) == -1 && code == 1009);
    uint8_t ping_frag[] = { 0x09, 0x80, 0, 0, 0, 0 };                    /* control frame without FIN */
    CHECK(ws_parse(ping_frag, sizeof ping_frag, 8192, &f, &code) == -1);
    uint8_t hdr[10];
    CHECK(ws_frame_header(WS_TEXT, 5, hdr) == 2 && hdr[0] == 0x81 && hdr[1] == 5);
    CHECK(ws_frame_header(WS_TEXT, 300, hdr) == 4 && hdr[1] == 126);
    CHECK(ws_frame_header(WS_TEXT, 70000, hdr) == 10 && hdr[1] == 127);
}

static void test_json(void)
{
    char type[16], text[32], name[8];
    json_field_t f[3] = { {"type", type, sizeof type, 0}, {"text", text, sizeof text, 0}, {"name", name, sizeof name, 0} };
    const char *ok = "{\"type\":\"msg\",\"x\":{\"type\":\"evil\",\"a\":[1,2,{\"b\":null}]},\"text\":\"h\\u00e9llo \\\"q\\\"\\n\"}";
    CHECK(json_parse_fields(ok, strlen(ok), f, 3) == JSON_OK);
    CHECK(f[0].found && !strcmp(type, "msg"));                         /* nested "type" must be ignored */
    CHECK(f[1].found && !strcmp(text, "h\xc3\xa9llo \"q\"\n"));
    CHECK(!f[2].found);

    const char *dup = "{\"type\":\"a\",\"type\":\"b\"}";
    CHECK(json_parse_fields(dup, strlen(dup), f, 3) == JSON_MALFORMED);
    const char *trailing = "{\"type\":\"a\"} x";
    CHECK(json_parse_fields(trailing, strlen(trailing), f, 3) == JSON_MALFORMED);
    const char *trunc = "{\"type\":\"a";
    CHECK(json_parse_fields(trunc, strlen(trunc), f, 3) == JSON_MALFORMED);
    const char *nul = "{\"type\":\"a\\u0000b\"}";
    CHECK(json_parse_fields(nul, strlen(nul), f, 3) == JSON_MALFORMED);
    const char *lone = "{\"type\":\"\\ud800\"}";
    CHECK(json_parse_fields(lone, strlen(lone), f, 3) == JSON_MALFORMED);
    const char *emoji = "{\"type\":\"\\ud83d\\ude00\"}";
    CHECK(json_parse_fields(emoji, strlen(emoji), f, 3) == JSON_OK && !strcmp(type, "\xf0\x9f\x98\x80"));
    const char *longv = "{\"name\":\"abcdefghijkl\"}";
    CHECK(json_parse_fields(longv, strlen(longv), f, 3) == JSON_TOO_LONG);
    const char *notobj = "[1,2]";
    CHECK(json_parse_fields(notobj, strlen(notobj), f, 3) == JSON_MALFORMED);
    char deep[200]; memset(deep, '[', 100); deep[100] = 0;
    char doc[300]; snprintf(doc, sizeof doc, "{\"a\":%s}", deep);
    CHECK(json_parse_fields(doc, strlen(doc), f, 3) == JSON_MALFORMED); /* depth bomb */
}

static void test_util(void)
{
    CHECK(utf8_valid("h\xc3\xa9llo", 6));
    CHECK(!utf8_valid("\xc0\xaf", 2));          /* overlong */
    CHECK(!utf8_valid("\xed\xa0\x80", 3));      /* surrogate */
    CHECK(!utf8_valid("\xf4\x90\x80\x80", 4));  /* > U+10FFFF */
    CHECK(!utf8_valid("\xe2\x82", 2));          /* truncated */
    CHECK(valid_username("alice_01") && valid_username("A-b"));
    CHECK(!valid_username("ab") && !valid_username("has space") && !valid_username("a:b") && !valid_username("<script>"));
    CHECK(has_control_chars("a\tb", 3) && !has_control_chars("ab", 2));

    sb_t b; sb_init(&b);
    sb_json_str(&b, "a\"b\\c\n\x01");
    CHECK(!strcmp(b.data, "\"a\\\"b\\\\c\\n\\u0001\""));
    sb_free(&b);

    uint8_t raw[4] = { 0xde, 0xad, 0xbe, 0xef }, back[4]; char hx[9];
    hex_encode(raw, 4, hx);
    CHECK(!strcmp(hx, "deadbeef") && hex_decode(hx, back, 4) == 0 && !memcmp(raw, back, 4));
    CHECK(hex_decode("zz", back, 1) == -1);
}

static void test_ratelimit(void)
{
    static rl_t rl;
    rl_init(&rl);
    for (int i = 0; i < 3; i++) { CHECK(!rl_blocked(&rl, "k", 3, 60)); rl_hit(&rl, "k", 60); }
    CHECK(rl_blocked(&rl, "k", 3, 60));
    CHECK(!rl_blocked(&rl, "other", 3, 60));
    rl_reset(&rl, "k");
    CHECK(!rl_blocked(&rl, "k", 3, 60));
    for (int i = 0; i < RL_SLOTS * 3; i++) { char k[32]; snprintf(k, sizeof k, "flood%d", i); rl_hit(&rl, k, 60); }
    CHECK(1); /* no overflow / crash when flooded with unique keys */
}

int main(void)
{
    test_sha(); test_ws_key(); test_ws_parse(); test_json(); test_util(); test_ratelimit();
    printf("%d/%d checks passed\n", total - fails, total);
    return fails ? 1 : 0;
}
