/**
 * @file ipfix_errors.c
 * @brief Error-path tests: bad version, truncated, unknown template, etc.
 */

#include "ipfix.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

static int drain_find_error(ipfix_ctx_t *ctx, ipfix_error_code_t want)
{
    ipfix_event_t ev;
    while (ipfix_next_event(ctx, &ev) == 1) {
        if (ev.type == IPFIX_EVENT_ERROR && ev.data.error.code == want) {
            return 1;
        }
    }
    return 0;
}

static void test_bad_version(void)
{
    uint8_t buf[16];
    ipfix_ctx_t *ctx = ipfix_create();

    memset(buf, 0, sizeof(buf));
    wr16(buf + 0, 9);   /* NetFlow v9, not IPFIX */
    wr16(buf + 2, 16);
    wr32(buf + 4, 1);
    wr32(buf + 8, 1);
    wr32(buf + 12, 1);

    assert(ipfix_feed_message(ctx, buf, sizeof(buf)) != 0);
    assert(drain_find_error(ctx, IPFIX_ERR_BAD_VERSION));
    ipfix_destroy(ctx);
    printf("  PASS test_bad_version\n");
}

static void test_truncated_header(void)
{
    uint8_t buf[8] = {0};
    ipfix_ctx_t *ctx = ipfix_create();

    wr16(buf + 0, 10);
    wr16(buf + 2, 16);
    assert(ipfix_feed_message(ctx, buf, sizeof(buf)) != 0);
    assert(drain_find_error(ctx, IPFIX_ERR_TRUNCATED));
    ipfix_destroy(ctx);
    printf("  PASS test_truncated_header\n");
}

static void test_bad_length(void)
{
    uint8_t buf[16];
    ipfix_ctx_t *ctx = ipfix_create();

    memset(buf, 0, sizeof(buf));
    wr16(buf + 0, 10);
    wr16(buf + 2, 8); /* less than header size */
    assert(ipfix_feed_message(ctx, buf, sizeof(buf)) != 0);
    assert(drain_find_error(ctx, IPFIX_ERR_BAD_LENGTH));
    ipfix_destroy(ctx);
    printf("  PASS test_bad_length\n");
}

static void test_unknown_template(void)
{
    /* Data set with no prior template. */
    uint8_t buf[32];
    const uint16_t data_set_len = 12;
    const uint16_t msg_len = (uint16_t)(16 + data_set_len);
    size_t off;
    ipfix_ctx_t *ctx = ipfix_create();

    memset(buf, 0, msg_len);
    wr16(buf + 0, 10);
    wr16(buf + 2, msg_len);
    wr32(buf + 4, 1);
    wr32(buf + 8, 1);
    wr32(buf + 12, 1);
    off = 16;
    wr16(buf + off, 999); /* unknown template */
    wr16(buf + off + 2, data_set_len);
    off += 4;
    wr32(buf + off, 0x01020304u);
    off += 4;
    wr32(buf + off, 0x05060708u);

    assert(ipfix_feed_message(ctx, buf, msg_len) == 0);
    assert(drain_find_error(ctx, IPFIX_ERR_UNKNOWN_TEMPLATE));
    ipfix_destroy(ctx);
    printf("  PASS test_unknown_template\n");
}

static void test_drop_unknown_sets(void)
{
    uint8_t buf[32];
    const uint16_t data_set_len = 12;
    const uint16_t msg_len = (uint16_t)(16 + data_set_len);
    size_t off;
    ipfix_config_t cfg = ipfix_default_config();
    ipfix_ctx_t *ctx;
    ipfix_event_t ev;
    int saw_error = 0;

    cfg.drop_unknown_sets = 1;
    ctx = ipfix_create_with_config(IPFIX_ROLE_COLLECTOR, &cfg);
    assert(ctx != NULL);

    memset(buf, 0, msg_len);
    wr16(buf + 0, 10);
    wr16(buf + 2, msg_len);
    wr32(buf + 4, 1);
    wr32(buf + 8, 1);
    wr32(buf + 12, 1);
    off = 16;
    wr16(buf + off, 999);
    wr16(buf + off + 2, data_set_len);
    off += 4;
    wr32(buf + off, 1);
    off += 4;
    wr32(buf + off, 2);

    assert(ipfix_feed_message(ctx, buf, msg_len) == 0);
    while (ipfix_next_event(ctx, &ev) == 1) {
        if (ev.type == IPFIX_EVENT_ERROR) {
            saw_error = 1;
        }
    }
    assert(!saw_error);
    ipfix_destroy(ctx);
    printf("  PASS test_drop_unknown_sets\n");
}

static void test_null_args(void)
{
    assert(ipfix_feed_input(NULL, (const uint8_t *)"x", 1) != 0);
    assert(ipfix_next_event(NULL, NULL) != 0);
    assert(ipfix_has_pending_events(NULL) == 0);
    assert(ipfix_event_count(NULL) == 0);
    assert(ipfix_reset(NULL) != 0);
    printf("  PASS test_null_args\n");
}

static void test_queue_overflow(void)
{
    /* Tiny event queue; feed a message that produces many events. */
    ipfix_config_t cfg = ipfix_default_config();
    ipfix_ctx_t *ctx;
    uint8_t buf[256];
    const uint16_t field_count = 1;
    const uint16_t tmpl_set_len = (uint16_t)(4 + 4 + field_count * 4);
    /* Many 4-byte records in data set */
    const int nrecords = 32;
    const uint16_t data_set_len = (uint16_t)(4 + nrecords * 4);
    const uint16_t msg_len = (uint16_t)(16 + tmpl_set_len + data_set_len);
    size_t off;
    int i;
    ipfix_event_t ev;
    int saw_overflow = 0;

    cfg.event_queue_size = 4;
    ctx = ipfix_create_with_config(IPFIX_ROLE_COLLECTOR, &cfg);
    assert(ctx != NULL);

    memset(buf, 0, msg_len);
    wr16(buf + 0, 10);
    wr16(buf + 2, msg_len);
    wr32(buf + 4, 1);
    wr32(buf + 8, 1);
    wr32(buf + 12, 1);
    off = 16;
    wr16(buf + off, 2);
    wr16(buf + off + 2, tmpl_set_len);
    off += 4;
    wr16(buf + off, 256);
    wr16(buf + off + 2, 1);
    off += 4;
    wr16(buf + off, 8);
    wr16(buf + off + 2, 4);
    off += 4;

    wr16(buf + off, 256);
    wr16(buf + off + 2, data_set_len);
    off += 4;
    for (i = 0; i < nrecords; i++) {
        wr32(buf + off, (uint32_t)i);
        off += 4;
    }

    assert(ipfix_feed_message(ctx, buf, msg_len) == 0);
    while (ipfix_next_event(ctx, &ev) == 1) {
        if (ev.type == IPFIX_EVENT_QUEUE_OVERFLOW) {
            saw_overflow = 1;
        }
    }
    assert(saw_overflow);
    assert(ipfix_dropped_count(ctx) > 0);
    ipfix_destroy(ctx);
    printf("  PASS test_queue_overflow\n");
}

int main(void)
{
    printf("ipfix_errors:\n");
    test_bad_version();
    test_truncated_header();
    test_bad_length();
    test_unknown_template();
    test_drop_unknown_sets();
    test_null_args();
    test_queue_overflow();
    printf("All error tests passed.\n");
    return 0;
}
