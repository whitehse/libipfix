/**
 * @file ipfix_dialectic.c
 * @brief Dialectic tests: multi-message template reuse, options, withdraw,
 *        multi-record sets, reset retains templates.
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

/* Template-only message: template 300 with srcIPv4 + dstIPv4 + ports. */
static size_t build_template_only(uint8_t *buf, size_t buflen, uint16_t tid)
{
    const uint16_t field_count = 4;
    const uint16_t tmpl_set_len = (uint16_t)(4 + 4 + field_count * 4);
    const uint16_t msg_len = (uint16_t)(16 + tmpl_set_len);
    size_t off;
    uint16_t ies[] = {8, 12, 7, 11};
    uint16_t lens[] = {4, 4, 2, 2};
    int i;

    assert(msg_len <= buflen);
    memset(buf, 0, msg_len);
    wr16(buf + 0, 10);
    wr16(buf + 2, msg_len);
    wr32(buf + 4, 1000);
    wr32(buf + 8, 1);
    wr32(buf + 12, 7);
    off = 16;
    wr16(buf + off, 2);
    wr16(buf + off + 2, tmpl_set_len);
    off += 4;
    wr16(buf + off, tid);
    wr16(buf + off + 2, field_count);
    off += 4;
    for (i = 0; i < field_count; i++) {
        wr16(buf + off, ies[i]);
        wr16(buf + off + 2, lens[i]);
        off += 4;
    }
    return msg_len;
}

/* Data-only message using previously learned template. */
static size_t build_data_only(uint8_t *buf, size_t buflen, uint16_t tid,
                              uint32_t src, uint32_t dst,
                              uint16_t sport, uint16_t dport)
{
    const uint16_t record_len = 4 + 4 + 2 + 2;
    const uint16_t data_set_len = (uint16_t)(4 + record_len);
    const uint16_t msg_len = (uint16_t)(16 + data_set_len);
    size_t off;

    assert(msg_len <= buflen);
    memset(buf, 0, msg_len);
    wr16(buf + 0, 10);
    wr16(buf + 2, msg_len);
    wr32(buf + 4, 1001);
    wr32(buf + 8, 2);
    wr32(buf + 12, 7);
    off = 16;
    wr16(buf + off, tid);
    wr16(buf + off + 2, data_set_len);
    off += 4;
    wr32(buf + off, src);
    off += 4;
    wr32(buf + off, dst);
    off += 4;
    wr16(buf + off, sport);
    off += 2;
    wr16(buf + off, dport);
    off += 2;
    (void)off;
    return msg_len;
}

/* Options template: scope = observationDomainId, non-scope = samplingInterval. */
static size_t build_options_template_and_data(uint8_t *buf, size_t buflen)
{
    /* options template set:
     *  set header 4
     *  tid + fcount + scope_count = 6
     *  2 field specs * 4 = 8
     *  total set = 18
     * data set for tid 400:
     *  set header 4 + odid 4 + sampling 4 = 12
     */
    const uint16_t opt_set_len = 18;
    const uint16_t data_set_len = 12;
    const uint16_t msg_len = (uint16_t)(16 + opt_set_len + data_set_len);
    size_t off;

    assert(msg_len <= buflen);
    memset(buf, 0, msg_len);
    wr16(buf + 0, 10);
    wr16(buf + 2, msg_len);
    wr32(buf + 4, 2000);
    wr32(buf + 8, 5);
    wr32(buf + 12, 99);
    off = 16;

    /* Options template set id=3 */
    wr16(buf + off, 3);
    wr16(buf + off + 2, opt_set_len);
    off += 4;
    wr16(buf + off, 400);      /* template id */
    wr16(buf + off + 2, 2);    /* field count */
    wr16(buf + off + 4, 1);    /* scope field count */
    off += 6;
    wr16(buf + off, 149);      /* observationDomainId */
    wr16(buf + off + 2, 4);
    off += 4;
    wr16(buf + off, 34);       /* samplingInterval */
    wr16(buf + off + 2, 4);
    off += 4;

    /* Options data */
    wr16(buf + off, 400);
    wr16(buf + off + 2, data_set_len);
    off += 4;
    wr32(buf + off, 99);       /* scope ODID */
    off += 4;
    wr32(buf + off, 1000);     /* sampling interval */
    off += 4;
    (void)off;
    return msg_len;
}

/* Withdraw template 300. */
static size_t build_withdraw(uint8_t *buf, size_t buflen, uint16_t tid)
{
    const uint16_t tmpl_set_len = 8; /* header 4 + tid/fcount 4 */
    const uint16_t msg_len = (uint16_t)(16 + tmpl_set_len);
    size_t off;

    assert(msg_len <= buflen);
    memset(buf, 0, msg_len);
    wr16(buf + 0, 10);
    wr16(buf + 2, msg_len);
    wr32(buf + 4, 3000);
    wr32(buf + 8, 9);
    wr32(buf + 12, 7);
    off = 16;
    wr16(buf + off, 2);
    wr16(buf + off + 2, tmpl_set_len);
    off += 4;
    wr16(buf + off, tid);
    wr16(buf + off + 2, 0); /* field_count = 0 => withdraw */
    return msg_len;
}

static void test_template_then_data_across_messages(void)
{
    uint8_t buf[256];
    size_t len;
    ipfix_ctx_t *ctx = ipfix_create();
    ipfix_event_t ev;
    int saw_data = 0;

    len = build_template_only(buf, sizeof(buf), 300);
    assert(ipfix_feed_message(ctx, buf, len) == 0);
    while (ipfix_next_event(ctx, &ev) == 1) {
        /* drain */
    }
    assert(ipfix_template_count(ctx) == 1);

    len = build_data_only(buf, sizeof(buf), 300,
                          0x0A000001u, 0x0A000002u, 53, 53);
    assert(ipfix_feed_message(ctx, buf, len) == 0);
    while (ipfix_next_event(ctx, &ev) == 1) {
        if (ev.type == IPFIX_EVENT_DATA_RECORD) {
            saw_data = 1;
            assert(ev.data.record.src_ipv4 == 0x0A000001u);
            assert(ev.data.record.dst_ipv4 == 0x0A000002u);
            assert(ev.data.record.src_port == 53);
            assert(ev.data.record.dst_port == 53);
        }
    }
    assert(saw_data);
    ipfix_destroy(ctx);
    printf("  PASS test_template_then_data_across_messages\n");
}

static void test_options_template_and_data(void)
{
    uint8_t buf[256];
    size_t len = build_options_template_and_data(buf, sizeof(buf));
    ipfix_ctx_t *ctx = ipfix_create();
    ipfix_event_t ev;
    int saw_opt_tmpl = 0, saw_opt_data = 0;

    assert(ipfix_feed_message(ctx, buf, len) == 0);
    while (ipfix_next_event(ctx, &ev) == 1) {
        if (ev.type == IPFIX_EVENT_OPTIONS_TEMPLATE) {
            saw_opt_tmpl = 1;
            assert(ev.data.tmpl.template_id == 400);
            assert(ev.data.tmpl.is_options == 1);
            assert(ev.data.tmpl.scope_field_count == 1);
            assert(ev.data.tmpl.fields[0].is_scope == 1);
            assert(ev.data.tmpl.fields[1].is_scope == 0);
        }
        if (ev.type == IPFIX_EVENT_OPTIONS_DATA) {
            saw_opt_data = 1;
            assert(ev.data.record.is_options == 1);
            assert(ev.data.record.field_count == 2);
            assert(ev.data.record.fields[0].element_id == 149);
            assert(ev.data.record.fields[0].v.u64 == 99);
            assert(ev.data.record.fields[1].element_id == 34);
            assert(ev.data.record.fields[1].v.u64 == 1000);
        }
    }
    assert(saw_opt_tmpl);
    assert(saw_opt_data);
    ipfix_destroy(ctx);
    printf("  PASS test_options_template_and_data\n");
}

static void test_template_withdraw(void)
{
    uint8_t buf[256];
    size_t len;
    ipfix_ctx_t *ctx = ipfix_create();
    ipfix_event_t ev;
    int saw_withdraw = 0;

    len = build_template_only(buf, sizeof(buf), 300);
    assert(ipfix_feed_message(ctx, buf, len) == 0);
    while (ipfix_next_event(ctx, &ev) == 1) { }
    assert(ipfix_template_count(ctx) == 1);

    len = build_withdraw(buf, sizeof(buf), 300);
    assert(ipfix_feed_message(ctx, buf, len) == 0);
    while (ipfix_next_event(ctx, &ev) == 1) {
        if (ev.type == IPFIX_EVENT_TEMPLATE_WITHDRAW) {
            saw_withdraw = 1;
            assert(ev.data.tmpl.template_id == 300);
        }
    }
    assert(saw_withdraw);
    assert(ipfix_template_count(ctx) == 0);
    ipfix_destroy(ctx);
    printf("  PASS test_template_withdraw\n");
}

static void test_reset_retains_templates(void)
{
    uint8_t buf[256];
    size_t len;
    ipfix_ctx_t *ctx = ipfix_create();
    ipfix_event_t ev;
    int saw_data = 0;

    len = build_template_only(buf, sizeof(buf), 300);
    assert(ipfix_feed_message(ctx, buf, len) == 0);
    while (ipfix_next_event(ctx, &ev) == 1) { }

    assert(ipfix_reset(ctx) == 0);
    assert(ipfix_template_count(ctx) == 1);
    assert(ipfix_event_count(ctx) == 0);

    len = build_data_only(buf, sizeof(buf), 300,
                          0x01020304u, 0x05060708u, 1, 2);
    assert(ipfix_feed_message(ctx, buf, len) == 0);
    while (ipfix_next_event(ctx, &ev) == 1) {
        if (ev.type == IPFIX_EVENT_DATA_RECORD) {
            saw_data = 1;
        }
    }
    assert(saw_data);

    assert(ipfix_clear_templates(ctx) == 0);
    assert(ipfix_template_count(ctx) == 0);
    ipfix_destroy(ctx);
    printf("  PASS test_reset_retains_templates\n");
}

static void test_multi_record_data_set(void)
{
    /* Template + data set with two records (same template 301). */
    uint8_t buf[256];
    const uint16_t field_count = 2;
    const uint16_t tmpl_set_len = (uint16_t)(4 + 4 + field_count * 4);
    const uint16_t record_len = 4 + 4; /* two IPv4 */
    const uint16_t data_set_len = (uint16_t)(4 + 2 * record_len);
    const uint16_t msg_len = (uint16_t)(16 + tmpl_set_len + data_set_len);
    size_t off;
    ipfix_ctx_t *ctx;
    ipfix_event_t ev;
    int records = 0;

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
    wr16(buf + off, 301);
    wr16(buf + off + 2, field_count);
    off += 4;
    wr16(buf + off, 8); wr16(buf + off + 2, 4); off += 4;
    wr16(buf + off, 12); wr16(buf + off + 2, 4); off += 4;

    wr16(buf + off, 301);
    wr16(buf + off + 2, data_set_len);
    off += 4;
    wr32(buf + off, 0x0A000001u); off += 4;
    wr32(buf + off, 0x0A000002u); off += 4;
    wr32(buf + off, 0x0A000003u); off += 4;
    wr32(buf + off, 0x0A000004u); off += 4;
    (void)off;

    ctx = ipfix_create();
    assert(ipfix_feed_message(ctx, buf, msg_len) == 0);
    while (ipfix_next_event(ctx, &ev) == 1) {
        if (ev.type == IPFIX_EVENT_DATA_RECORD) {
            records++;
        }
    }
    assert(records == 2);
    ipfix_destroy(ctx);
    printf("  PASS test_multi_record_data_set\n");
}

static void test_enterprise_field(void)
{
    /* Template with enterprise IE: id with E-bit, enterprise number 9 (Cisco). */
    uint8_t buf[256];
    const uint16_t tmpl_set_len = 4 + 4 + 8; /* one enterprise field spec */
    const uint16_t data_set_len = 4 + 4;
    const uint16_t msg_len = (uint16_t)(16 + tmpl_set_len + data_set_len);
    size_t off;
    ipfix_ctx_t *ctx;
    ipfix_event_t ev;
    int saw = 0;

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
    wr16(buf + off, 500);
    wr16(buf + off + 2, 1);
    off += 4;
    /* E-bit set | element id 123, length 4, enterprise 9 */
    wr16(buf + off, (uint16_t)(0x8000u | 123u));
    wr16(buf + off + 2, 4);
    wr32(buf + off + 4, 9);
    off += 8;

    wr16(buf + off, 500);
    wr16(buf + off + 2, data_set_len);
    off += 4;
    wr32(buf + off, 0xDEADBEEFu);

    ctx = ipfix_create();
    assert(ipfix_feed_message(ctx, buf, msg_len) == 0);
    while (ipfix_next_event(ctx, &ev) == 1) {
        if (ev.type == IPFIX_EVENT_TEMPLATE) {
            assert(ev.data.tmpl.fields[0].element_id == 123);
            assert(ev.data.tmpl.fields[0].enterprise_number == 9);
        }
        if (ev.type == IPFIX_EVENT_DATA_RECORD) {
            const ipfix_field_t *f =
                ipfix_record_find_enterprise_field(&ev.data.record, 9, 123);
            assert(f != NULL);
            assert(f->v.u64 == 0xDEADBEEFu);
            saw = 1;
        }
    }
    assert(saw);
    ipfix_destroy(ctx);
    printf("  PASS test_enterprise_field\n");
}

int main(void)
{
    printf("ipfix_dialectic:\n");
    test_template_then_data_across_messages();
    test_options_template_and_data();
    test_template_withdraw();
    test_reset_retains_templates();
    test_multi_record_data_set();
    test_enterprise_field();
    printf("All dialectic tests passed.\n");
    return 0;
}
