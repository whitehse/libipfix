/**
 * @file ipfix_smoke.c
 * @brief Smoke tests: message header, template, data record with 5-tuple.
 */

#include "ipfix.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ── wire builders ───────────────────────────────────────────────────── */

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

static void wr64(uint8_t *p, uint64_t v)
{
    wr32(p, (uint32_t)(v >> 32));
    wr32(p + 4, (uint32_t)(v & 0xFFFFFFFFu));
}

/**
 * Build a minimal IPFIX message:
 *   Template ID 256: srcIPv4, dstIPv4, srcPort, dstPort, protocol,
 *                    octetDelta, packetDelta, flowStartMs, flowEndMs
 *   One data record with known values.
 *
 * Returns total length written into buf.
 */
static size_t build_flow_message(uint8_t *buf, size_t buflen)
{
    /* Layout:
     *  [0..15]  message header
     *  [16..19] template set header (set_id=2, length=...)
     *  [20..23] template id=256, field_count=9
     *  [24..]   9 * 4-byte field specs
     *  [...]    data set header (set_id=256)
     *  [...]    one data record
     */
    const uint16_t field_count = 9;
    const uint16_t tmpl_set_len = (uint16_t)(4 + 4 + field_count * 4);
    const uint16_t record_len =
        4 + 4 + 2 + 2 + 1 + 8 + 8 + 8 + 8; /* fixed fields */
    const uint16_t data_set_len = (uint16_t)(4 + record_len);
    const uint16_t msg_len = (uint16_t)(16 + tmpl_set_len + data_set_len);
    size_t off = 0;
    uint16_t ies[] = {8, 12, 7, 11, 4, 1, 2, 152, 153};
    uint16_t lens[] = {4, 4, 2, 2, 1, 8, 8, 8, 8};
    int i;

    assert(msg_len <= buflen);
    memset(buf, 0, msg_len);

    /* Message header */
    wr16(buf + 0, 10);                 /* version */
    wr16(buf + 2, msg_len);
    wr32(buf + 4, 1700000000u);        /* export time */
    wr32(buf + 8, 1u);                 /* sequence */
    wr32(buf + 12, 42u);               /* ODID */
    off = 16;

    /* Template set */
    wr16(buf + off, 2);                /* set id = template */
    wr16(buf + off + 2, tmpl_set_len);
    off += 4;
    wr16(buf + off, 256);              /* template id */
    wr16(buf + off + 2, field_count);
    off += 4;
    for (i = 0; i < field_count; i++) {
        wr16(buf + off, ies[i]);
        wr16(buf + off + 2, lens[i]);
        off += 4;
    }

    /* Data set */
    wr16(buf + off, 256);              /* set id = template id */
    wr16(buf + off + 2, data_set_len);
    off += 4;

    /* Record: 192.0.2.1 -> 198.51.100.10 :12345->80 proto 6, 1500 octets, 10 pkts */
    wr32(buf + off, 0xC0000201u);      /* 192.0.2.1 */
    off += 4;
    wr32(buf + off, 0xC633640Au);      /* 198.51.100.10 */
    off += 4;
    wr16(buf + off, 12345);
    off += 2;
    wr16(buf + off, 80);
    off += 2;
    buf[off++] = 6;                    /* TCP */
    wr64(buf + off, 1500);
    off += 8;
    wr64(buf + off, 10);
    off += 8;
    wr64(buf + off, 1700000000000ull);
    off += 8;
    wr64(buf + off, 1700000001000ull);
    off += 8;

    assert(off == msg_len);
    return msg_len;
}

/* ── tests ───────────────────────────────────────────────────────────── */

static void test_create_destroy(void)
{
    ipfix_ctx_t *ctx = ipfix_create();
    assert(ctx != NULL);
    assert(ipfix_event_count(ctx) == 0);
    assert(ipfix_template_count(ctx) == 0);
    ipfix_destroy(ctx);
    ipfix_destroy(NULL);
    printf("  PASS test_create_destroy\n");
}

static void test_default_config(void)
{
    ipfix_config_t cfg = ipfix_default_config();
    assert(cfg.event_queue_size == 256);
    assert(cfg.max_message_size == 64u * 1024u);
    assert(cfg.max_templates == 256);
    printf("  PASS test_default_config\n");
}

static void test_template_and_data_record(void)
{
    uint8_t buf[512];
    size_t len = build_flow_message(buf, sizeof(buf));
    ipfix_ctx_t *ctx = ipfix_create();
    ipfix_event_t ev;
    int saw_message = 0, saw_template = 0, saw_data = 0;
    char ipbuf[16];

    assert(ctx != NULL);
    assert(ipfix_feed_message(ctx, buf, len) == 0);

    while (ipfix_next_event(ctx, &ev) == 1) {
        switch (ev.type) {
        case IPFIX_EVENT_MESSAGE:
            saw_message = 1;
            assert(ev.message.version == 10);
            assert(ev.message.observation_domain_id == 42u);
            assert(ev.message.sequence_number == 1u);
            break;
        case IPFIX_EVENT_TEMPLATE:
            saw_template = 1;
            assert(ev.data.tmpl.template_id == 256);
            assert(ev.data.tmpl.field_count == 9);
            assert(ev.data.tmpl.is_options == 0);
            break;
        case IPFIX_EVENT_DATA_RECORD:
            saw_data = 1;
            assert(ev.data.record.template_id == 256);
            assert(ev.data.record.field_count == 9);
            assert(ev.data.record.has_src_ipv4);
            assert(ev.data.record.has_dst_ipv4);
            assert(ev.data.record.has_src_port);
            assert(ev.data.record.has_dst_port);
            assert(ev.data.record.has_protocol);
            assert(ev.data.record.has_octet_delta);
            assert(ev.data.record.has_packet_delta);
            assert(ev.data.record.src_ipv4 == 0xC0000201u);
            assert(ev.data.record.dst_ipv4 == 0xC633640Au);
            assert(ev.data.record.src_port == 12345);
            assert(ev.data.record.dst_port == 80);
            assert(ev.data.record.protocol == 6);
            assert(ev.data.record.octet_delta == 1500);
            assert(ev.data.record.packet_delta == 10);
            assert(ev.data.record.flow_start_ms == 1700000000000ull);
            assert(ev.data.record.flow_end_ms == 1700000001000ull);
            ipfix_format_ipv4(ev.data.record.src_ipv4, ipbuf, sizeof(ipbuf));
            assert(strcmp(ipbuf, "192.0.2.1") == 0);
            break;
        case IPFIX_EVENT_SET_END:
        case IPFIX_EVENT_ERROR:
        case IPFIX_EVENT_QUEUE_OVERFLOW:
        case IPFIX_EVENT_OPTIONS_TEMPLATE:
        case IPFIX_EVENT_OPTIONS_DATA:
        case IPFIX_EVENT_TEMPLATE_WITHDRAW:
            break;
        }
    }

    assert(saw_message);
    assert(saw_template);
    assert(saw_data);
    assert(ipfix_template_count(ctx) == 1);

    {
        ipfix_template_t t;
        assert(ipfix_get_template(ctx, 256, &t) == 1);
        assert(t.field_count == 9);
        assert(ipfix_get_template(ctx, 999, &t) == 0);
    }

    ipfix_destroy(ctx);
    printf("  PASS test_template_and_data_record\n");
}

static void test_feed_input_streaming(void)
{
    uint8_t buf[512];
    size_t len = build_flow_message(buf, sizeof(buf));
    ipfix_ctx_t *ctx = ipfix_create();
    ipfix_event_t ev;
    int saw_data = 0;
    size_t half;

    assert(ctx != NULL);
    half = len / 2;
    assert(ipfix_feed_input(ctx, buf, half) == 0);
    /* No complete message yet — no MESSAGE event expected, or maybe none */
    assert(ipfix_feed_input(ctx, buf + half, len - half) == 0);

    while (ipfix_next_event(ctx, &ev) == 1) {
        if (ev.type == IPFIX_EVENT_DATA_RECORD) {
            saw_data = 1;
            assert(ev.data.record.src_port == 12345);
        }
    }
    assert(saw_data);
    ipfix_destroy(ctx);
    printf("  PASS test_feed_input_streaming\n");
}

static void test_ie_name_helpers(void)
{
    assert(strcmp(ipfix_ie_name(8), "sourceIPv4Address") == 0);
    assert(strcmp(ipfix_ie_name(152), "flowStartMilliseconds") == 0);
    assert(ipfix_ie_name(65000) == NULL);
    assert(strcmp(ipfix_event_type_name(IPFIX_EVENT_DATA_RECORD),
                  "DATA_RECORD") == 0);
    assert(strcmp(ipfix_error_name(IPFIX_ERR_BAD_VERSION),
                  "BAD_VERSION") == 0);
    printf("  PASS test_ie_name_helpers\n");
}

static void test_record_find_field(void)
{
    uint8_t buf[512];
    size_t len = build_flow_message(buf, sizeof(buf));
    ipfix_ctx_t *ctx = ipfix_create();
    ipfix_event_t ev;
    const ipfix_field_t *f = NULL;

    assert(ipfix_feed_message(ctx, buf, len) == 0);
    while (ipfix_next_event(ctx, &ev) == 1) {
        if (ev.type == IPFIX_EVENT_DATA_RECORD) {
            f = ipfix_record_find_field(&ev.data.record,
                                        IPFIX_IE_sourceTransportPort);
            assert(f != NULL);
            assert(f->kind == IPFIX_VALUE_UINT);
            assert(f->v.u64 == 12345);
            assert(ipfix_record_find_field(&ev.data.record, 9999) == NULL);
        }
    }
    assert(f != NULL);
    ipfix_destroy(ctx);
    printf("  PASS test_record_find_field\n");
}

int main(void)
{
    printf("ipfix_smoke:\n");
    test_create_destroy();
    test_default_config();
    test_template_and_data_record();
    test_feed_input_streaming();
    test_ie_name_helpers();
    test_record_find_field();
    printf("All smoke tests passed.\n");
    return 0;
}
