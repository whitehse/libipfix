/**
 * @file ipfix_example.c
 * @brief Example: parse a synthetic IPFIX flow message and print records.
 *
 * Demonstrates the syscall-free feed/event API. In production the caller
 * would receive UDP datagrams (or TCP stream chunks) via io_uring/epoll
 * and pass them to ipfix_feed_input() / ipfix_feed_message().
 */

#include "ipfix.h"

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

static void wr64(uint8_t *p, uint64_t v)
{
    wr32(p, (uint32_t)(v >> 32));
    wr32(p + 4, (uint32_t)(v & 0xFFFFFFFFu));
}

static size_t build_sample(uint8_t *buf, size_t buflen)
{
    const uint16_t field_count = 7;
    const uint16_t tmpl_set_len = (uint16_t)(4 + 4 + field_count * 4);
    const uint16_t record_len = 4 + 4 + 2 + 2 + 1 + 8 + 8;
    const uint16_t data_set_len = (uint16_t)(4 + record_len);
    const uint16_t msg_len = (uint16_t)(16 + tmpl_set_len + data_set_len);
    size_t off = 0;
    uint16_t ies[] = {8, 12, 7, 11, 4, 1, 2};
    uint16_t lens[] = {4, 4, 2, 2, 1, 8, 8};
    int i;

    if (msg_len > buflen) {
        return 0;
    }
    memset(buf, 0, msg_len);

    wr16(buf + 0, 10);
    wr16(buf + 2, msg_len);
    wr32(buf + 4, 1710000000u);
    wr32(buf + 8, 1u);
    wr32(buf + 12, 1u);
    off = 16;

    wr16(buf + off, 2);
    wr16(buf + off + 2, tmpl_set_len);
    off += 4;
    wr16(buf + off, 256);
    wr16(buf + off + 2, field_count);
    off += 4;
    for (i = 0; i < (int)field_count; i++) {
        wr16(buf + off, ies[i]);
        wr16(buf + off + 2, lens[i]);
        off += 4;
    }

    wr16(buf + off, 256);
    wr16(buf + off + 2, data_set_len);
    off += 4;
    wr32(buf + off, 0xC0A8010Au); /* 192.168.1.10 */
    off += 4;
    wr32(buf + off, 0x08080808u); /* 8.8.8.8 */
    off += 4;
    wr16(buf + off, 54321);
    off += 2;
    wr16(buf + off, 53);
    off += 2;
    buf[off++] = 17; /* UDP */
    wr64(buf + off, 128);
    off += 8;
    wr64(buf + off, 1);
    off += 8;
    (void)off;
    return msg_len;
}

int main(void)
{
    uint8_t wire[256];
    size_t len = build_sample(wire, sizeof(wire));
    ipfix_ctx_t *ctx;
    ipfix_event_t ev;
    char src[16], dst[16];

    if (len == 0) {
        fprintf(stderr, "failed to build sample\n");
        return 1;
    }

    ctx = ipfix_create();
    if (!ctx) {
        fprintf(stderr, "ipfix_create failed\n");
        return 1;
    }

    /* In a real receiver:
     *   recvfrom(udp_fd, buf, ...) or io_uring completion
     *   ipfix_feed_message(ctx, buf, n);
     */
    if (ipfix_feed_message(ctx, wire, len) != 0) {
        fprintf(stderr, "feed failed\n");
        ipfix_destroy(ctx);
        return 1;
    }

    printf("libipfix example — parsing synthetic flow export\n\n");

    while (ipfix_next_event(ctx, &ev) == 1) {
        printf("[%s]", ipfix_event_type_name(ev.type));
        switch (ev.type) {
        case IPFIX_EVENT_MESSAGE:
            printf(" version=%u len=%u export_time=%u seq=%u odid=%u\n",
                   ev.message.version, ev.message.length,
                   ev.message.export_time, ev.message.sequence_number,
                   ev.message.observation_domain_id);
            break;
        case IPFIX_EVENT_TEMPLATE:
            printf(" template_id=%u fields=%u\n",
                   ev.data.tmpl.template_id, ev.data.tmpl.field_count);
            break;
        case IPFIX_EVENT_DATA_RECORD:
            ipfix_format_ipv4(ev.data.record.src_ipv4, src, sizeof(src));
            ipfix_format_ipv4(ev.data.record.dst_ipv4, dst, sizeof(dst));
            printf(" %s:%u -> %s:%u proto=%u octets=%llu packets=%llu\n",
                   src, ev.data.record.src_port,
                   dst, ev.data.record.dst_port,
                   ev.data.record.protocol,
                   (unsigned long long)ev.data.record.octet_delta,
                   (unsigned long long)ev.data.record.packet_delta);
            break;
        case IPFIX_EVENT_ERROR:
            printf(" %s: %s\n",
                   ipfix_error_name(ev.data.error.code),
                   ev.data.error.message);
            break;
        default:
            printf("\n");
            break;
        }
    }

    printf("\nTemplates cached: %u\n", ipfix_template_count(ctx));
    ipfix_destroy(ctx);
    return 0;
}
