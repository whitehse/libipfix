/**
 * @file ipfix_fuzz.c
 * @brief libFuzzer harness for libipfix.
 *
 * Feeds untrusted bytes through both ingest paths, drains events, and
 * touches field/template helpers so enterprise registries and convenience
 * extracts are exercised under ASan/UBSan.
 */

#include "ipfix.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void drain_and_touch(ipfix_ctx_t *ctx)
{
    ipfix_event_t ev;
    while (ipfix_next_event(ctx, &ev) == 1) {
        if (ev.type == IPFIX_EVENT_DATA_RECORD ||
            ev.type == IPFIX_EVENT_OPTIONS_DATA) {
            const ipfix_data_record_t *rec = &ev.data.record;
            uint16_t i;
            for (i = 0; i < rec->field_count; i++) {
                const ipfix_field_t *f = &rec->fields[i];
                (void)ipfix_enterprise_ie_name(f->enterprise_number,
                                               f->element_id);
                (void)ipfix_enterprise_ie_datatype(f->enterprise_number,
                                                   f->element_id);
                (void)ipfix_record_find_enterprise_field(
                    rec, f->enterprise_number, f->element_id);
                if (f->enterprise_number == 0u) {
                    (void)ipfix_ie_name(f->element_id);
                    (void)ipfix_record_find_field(rec, f->element_id);
                }
                if (f->kind == IPFIX_VALUE_IPV4) {
                    char buf[16];
                    (void)ipfix_format_ipv4(f->v.ipv4, buf, sizeof(buf));
                } else if (f->kind == IPFIX_VALUE_IPV6) {
                    char buf[40];
                    (void)ipfix_format_ipv6(f->v.ipv6, buf, sizeof(buf));
                }
            }
            (void)rec->has_src_ipv4;
            (void)rec->octet_delta;
        } else if (ev.type == IPFIX_EVENT_TEMPLATE ||
                   ev.type == IPFIX_EVENT_OPTIONS_TEMPLATE) {
            ipfix_template_t out;
            (void)ipfix_get_template(ctx, ev.data.tmpl.template_id, &out);
        }
        (void)ipfix_event_type_name(ev.type);
        if (ev.type == IPFIX_EVENT_ERROR) {
            (void)ipfix_error_name(ev.data.error.code);
        }
    }
    (void)ipfix_has_pending_events(ctx);
    (void)ipfix_event_count(ctx);
    (void)ipfix_dropped_count(ctx);
    (void)ipfix_template_count(ctx);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ipfix_ctx_t *ctx;
    ipfix_config_t cfg;

    /* Bound input to avoid huge reassembly buffers dominating runtime. */
    if (size > 64u * 1024u) {
        size = 64u * 1024u;
    }

    cfg = ipfix_default_config();
    /* Smaller queues keep the harness light under high iteration rates. */
    cfg.event_queue_size = 64;
    cfg.max_templates = 64;
    cfg.max_message_size = 64u * 1024u;
    cfg.max_input_buffer = 128u * 1024u;
    if (size > 0u && (data[0] & 1u) != 0u) {
        cfg.drop_unknown_sets = 1;
    }

    ctx = ipfix_create_with_config(IPFIX_ROLE_COLLECTOR, &cfg);
    if (!ctx) {
        return 0;
    }

    if (size > 0u) {
        /* Streaming reassembly path (TCP-style chunks). */
        if (size >= 3u) {
            size_t a = size / 3u;
            size_t b = size / 3u;
            size_t c = size - a - b;
            (void)ipfix_feed_input(ctx, data, a);
            (void)ipfix_feed_input(ctx, data + a, b);
            (void)ipfix_feed_input(ctx, data + a + b, c);
        } else {
            (void)ipfix_feed_input(ctx, data, size);
        }
        drain_and_touch(ctx);

        (void)ipfix_reset(ctx);

        /* Datagram path (complete message buffer). */
        (void)ipfix_feed_message(ctx, data, size);
        drain_and_touch(ctx);

        /* Cross-message template reuse: feed again after reset (templates retained). */
        (void)ipfix_reset(ctx);
        (void)ipfix_feed_message(ctx, data, size);
        drain_and_touch(ctx);

        (void)ipfix_clear_templates(ctx);
        (void)ipfix_feed_message(ctx, data, size);
        drain_and_touch(ctx);
    }

    ipfix_destroy(ctx);
    return 0;
}
