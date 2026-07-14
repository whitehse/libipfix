/**
 * @file ipfix.c
 * @brief IPFIX (RFC 7011) receiver implementation.
 *
 * Pure C, syscall-free, callback-free. Caller feeds wire bytes and
 * pulls events from a fixed-size ring buffer.
 */

#include "ipfix.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── internal constants ──────────────────────────────────────────────── */

#define DEFAULT_QUEUE_SIZE     256u
#define DEFAULT_MAX_MESSAGE    (64u * 1024u)
#define DEFAULT_MAX_TEMPLATES  256u
#define DEFAULT_MAX_INPUT      (256u * 1024u)

#define IPFIX_SET_TEMPLATE          2u
#define IPFIX_SET_OPTIONS_TEMPLATE  3u
#define IPFIX_MSG_HEADER_LEN        16u
#define IPFIX_SET_HEADER_LEN        4u
#define IPFIX_VARLEN_MARKER         65535u

/* ── context ─────────────────────────────────────────────────────────── */

struct ipfix_ctx {
    ipfix_role_t     role;
    ipfix_config_t   cfg;

    /* event ring buffer */
    ipfix_event_t   *events;
    uint32_t         queue_size;
    uint32_t         head;
    uint32_t         tail;
    uint32_t         count;
    uint64_t         dropped;

    /* template cache */
    ipfix_template_t *templates;
    uint32_t          template_cap;
    uint32_t          template_count;

    /* stream reassembly buffer (TCP / partial feeds) */
    uint8_t          *input_buf;
    size_t            input_len;
    size_t            input_cap;

    /* last parsed message header (copied into events) */
    ipfix_message_header_t last_msg;
};

/* ── endian helpers (no system headers beyond stdint) ─────────────────── */

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static uint64_t rd_uint_be(const uint8_t *p, size_t len)
{
    uint64_t v = 0;
    size_t i;
    for (i = 0; i < len && i < 8; i++) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

/* ── event ring ──────────────────────────────────────────────────────── */

static void emit_event(ipfix_ctx_t *ctx, const ipfix_event_t *ev)
{
    if (ctx->count >= ctx->queue_size) {
        /*
         * Ring full: replace the oldest slot (at head==tail when full)
         * with QUEUE_OVERFLOW and discard the new event. Count stays
         * capped; caller observes dropped_count.
         */
        ipfix_event_t overflow;
        memset(&overflow, 0, sizeof(overflow));
        overflow.type = IPFIX_EVENT_QUEUE_OVERFLOW;
        overflow.message = ctx->last_msg;
        ctx->events[ctx->head] = overflow;
        ctx->head = (ctx->head + 1u) % ctx->queue_size;
        /* tail unchanged: next read yields OVERFLOW (or prior events first
         * if head had already lapped — when full, head==tail so OVERFLOW
         * is exactly the next unread after previous drains). */
        ctx->dropped++;
        return;
    }
    ctx->events[ctx->head] = *ev;
    ctx->head = (ctx->head + 1u) % ctx->queue_size;
    ctx->count++;
}

static void emit_error(ipfix_ctx_t *ctx, ipfix_error_code_t code,
                       uint32_t offset, const char *msg)
{
    ipfix_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = IPFIX_EVENT_ERROR;
    ev.message = ctx->last_msg;
    ev.data.error.code = code;
    ev.data.error.offset = offset;
    if (msg) {
        strncpy(ev.data.error.message, msg, sizeof(ev.data.error.message) - 1u);
    }
    emit_event(ctx, &ev);
}

/* ── template cache ──────────────────────────────────────────────────── */

static ipfix_template_t *find_template(ipfix_ctx_t *ctx, uint16_t id)
{
    uint32_t i;
    for (i = 0; i < ctx->template_count; i++) {
        if (ctx->templates[i].template_id == id) {
            return &ctx->templates[i];
        }
    }
    return NULL;
}

static const ipfix_template_t *find_template_const(const ipfix_ctx_t *ctx,
                                                   uint16_t id)
{
    uint32_t i;
    for (i = 0; i < ctx->template_count; i++) {
        if (ctx->templates[i].template_id == id) {
            return &ctx->templates[i];
        }
    }
    return NULL;
}

static int store_template(ipfix_ctx_t *ctx, const ipfix_template_t *tmpl)
{
    ipfix_template_t *existing = find_template(ctx, tmpl->template_id);
    if (existing) {
        *existing = *tmpl;
        return 0;
    }
    if (ctx->template_count >= ctx->template_cap) {
        return -1;
    }
    ctx->templates[ctx->template_count++] = *tmpl;
    return 0;
}

static void withdraw_template(ipfix_ctx_t *ctx, uint16_t id)
{
    uint32_t i;
    for (i = 0; i < ctx->template_count; i++) {
        if (ctx->templates[i].template_id == id) {
            /* compact */
            if (i + 1u < ctx->template_count) {
                memmove(&ctx->templates[i], &ctx->templates[i + 1u],
                        (ctx->template_count - i - 1u) * sizeof(ipfix_template_t));
            }
            ctx->template_count--;
            return;
        }
    }
}

/* ── field decoding ──────────────────────────────────────────────────── */

static void decode_field_value(ipfix_field_t *f, const uint8_t *data,
                               uint16_t len)
{
    f->length = len;
    f->kind = IPFIX_VALUE_RAW;
    memset(&f->v, 0, sizeof(f->v));

    if (len == 0) {
        return;
    }

    /* Classify by well-known IANA IE when enterprise is 0. */
    if (f->enterprise_number == 0) {
        switch (f->element_id) {
        case IPFIX_IE_sourceIPv4Address:
        case IPFIX_IE_destinationIPv4Address:
        case IPFIX_IE_ipNextHopIPv4Address:
        case IPFIX_IE_bgpNextHopIPv4Address:
        case IPFIX_IE_exporterIPv4Address:
            if (len == 4) {
                f->kind = IPFIX_VALUE_IPV4;
                f->v.ipv4 = rd32(data);
                return;
            }
            break;

        case IPFIX_IE_sourceIPv6Address:
        case IPFIX_IE_destinationIPv6Address:
        case IPFIX_IE_exporterIPv6Address:
            if (len == 16) {
                f->kind = IPFIX_VALUE_IPV6;
                memcpy(f->v.ipv6, data, 16);
                return;
            }
            break;

        case IPFIX_IE_sourceMacAddress:
        case IPFIX_IE_destinationMacAddress:
            if (len == 6) {
                f->kind = IPFIX_VALUE_MAC;
                memcpy(f->v.mac, data, 6);
                return;
            }
            break;

        case IPFIX_IE_applicationDescription:
            f->kind = IPFIX_VALUE_STRING;
            {
                size_t copy = len;
                if (copy >= IPFIX_MAX_FIELD_VALUE_LEN) {
                    copy = IPFIX_MAX_FIELD_VALUE_LEN - 1u;
                }
                memcpy(f->v.raw, data, copy);
                f->v.raw[copy] = 0;
                f->length = (uint16_t)copy;
            }
            return;

        default:
            /* Integer-like fixed widths */
            if (len <= 8) {
                f->kind = IPFIX_VALUE_UINT;
                f->v.u64 = rd_uint_be(data, len);
                return;
            }
            break;
        }
    } else {
        /* Enterprise fields: prefer integer if short, else raw. */
        if (len <= 8) {
            f->kind = IPFIX_VALUE_UINT;
            f->v.u64 = rd_uint_be(data, len);
            return;
        }
    }

    /* Fallback: raw copy (truncated to max). */
    {
        size_t copy = len;
        if (copy > IPFIX_MAX_FIELD_VALUE_LEN) {
            copy = IPFIX_MAX_FIELD_VALUE_LEN;
        }
        memcpy(f->v.raw, data, copy);
        f->length = (uint16_t)copy;
        f->kind = IPFIX_VALUE_RAW;
    }
}

static void fill_convenience(ipfix_data_record_t *rec)
{
    uint16_t i;
    for (i = 0; i < rec->field_count; i++) {
        const ipfix_field_t *f = &rec->fields[i];
        if (f->enterprise_number != 0) {
            continue;
        }
        switch (f->element_id) {
        case IPFIX_IE_sourceIPv4Address:
            if (f->kind == IPFIX_VALUE_IPV4) {
                rec->has_src_ipv4 = 1;
                rec->src_ipv4 = f->v.ipv4;
            }
            break;
        case IPFIX_IE_destinationIPv4Address:
            if (f->kind == IPFIX_VALUE_IPV4) {
                rec->has_dst_ipv4 = 1;
                rec->dst_ipv4 = f->v.ipv4;
            }
            break;
        case IPFIX_IE_sourceTransportPort:
            if (f->kind == IPFIX_VALUE_UINT) {
                rec->has_src_port = 1;
                rec->src_port = (uint16_t)f->v.u64;
            }
            break;
        case IPFIX_IE_destinationTransportPort:
            if (f->kind == IPFIX_VALUE_UINT) {
                rec->has_dst_port = 1;
                rec->dst_port = (uint16_t)f->v.u64;
            }
            break;
        case IPFIX_IE_protocolIdentifier:
            if (f->kind == IPFIX_VALUE_UINT) {
                rec->has_protocol = 1;
                rec->protocol = (uint8_t)f->v.u64;
            }
            break;
        case IPFIX_IE_octetDeltaCount:
            if (f->kind == IPFIX_VALUE_UINT) {
                rec->has_octet_delta = 1;
                rec->octet_delta = f->v.u64;
            }
            break;
        case IPFIX_IE_packetDeltaCount:
            if (f->kind == IPFIX_VALUE_UINT) {
                rec->has_packet_delta = 1;
                rec->packet_delta = f->v.u64;
            }
            break;
        case IPFIX_IE_flowStartMilliseconds:
            if (f->kind == IPFIX_VALUE_UINT) {
                rec->has_flow_start_ms = 1;
                rec->flow_start_ms = f->v.u64;
            }
            break;
        case IPFIX_IE_flowEndMilliseconds:
            if (f->kind == IPFIX_VALUE_UINT) {
                rec->has_flow_end_ms = 1;
                rec->flow_end_ms = f->v.u64;
            }
            break;
        default:
            break;
        }
    }
}

/* ── parse field specifier ───────────────────────────────────────────── */

static int parse_field_spec(const uint8_t *p, size_t avail,
                            ipfix_field_spec_t *spec, size_t *consumed)
{
    uint16_t id_and_flag;
    if (avail < 4u) {
        return -1;
    }
    id_and_flag = rd16(p);
    spec->field_length = rd16(p + 2);
    spec->is_variable = (spec->field_length == IPFIX_VARLEN_MARKER) ? 1 : 0;
    spec->is_scope = 0;

    if (id_and_flag & 0x8000u) {
        /* Enterprise bit set */
        if (avail < 8u) {
            return -1;
        }
        spec->element_id = (uint16_t)(id_and_flag & 0x7FFFu);
        spec->enterprise_number = rd32(p + 4);
        *consumed = 8u;
    } else {
        spec->element_id = id_and_flag;
        spec->enterprise_number = 0;
        *consumed = 4u;
    }
    return 0;
}

/* ── template set ────────────────────────────────────────────────────── */

static int parse_template_set(ipfix_ctx_t *ctx, const uint8_t *set,
                              uint16_t set_len, uint32_t set_offset)
{
    size_t off = IPFIX_SET_HEADER_LEN;

    while (off + 4u <= set_len) {
        uint16_t tid = rd16(set + off);
        uint16_t fcount = rd16(set + off + 2);
        size_t rec_off = off + 4u;
        ipfix_template_t tmpl;
        uint16_t fi;
        ipfix_event_t ev;

        /* Padding: template id 0 is not valid for records; stop. */
        if (tid < 256u && fcount != 0u) {
            /* Residual padding zeros — stop parsing set. */
            break;
        }

        memset(&tmpl, 0, sizeof(tmpl));
        tmpl.template_id = tid;
        tmpl.field_count = fcount;
        tmpl.scope_field_count = 0;
        tmpl.is_options = 0;

        /* Withdrawal: field_count == 0 */
        if (fcount == 0u) {
            withdraw_template(ctx, tid);
            memset(&ev, 0, sizeof(ev));
            ev.type = IPFIX_EVENT_TEMPLATE_WITHDRAW;
            ev.message = ctx->last_msg;
            ev.data.tmpl = tmpl;
            emit_event(ctx, &ev);
            off = rec_off;
            continue;
        }

        if (fcount > IPFIX_MAX_FIELDS_PER_TEMPLATE) {
            emit_error(ctx, IPFIX_ERR_BAD_TEMPLATE, set_offset + (uint32_t)off,
                       "template field_count exceeds limit");
            return -1;
        }

        for (fi = 0; fi < fcount; fi++) {
            size_t consumed = 0;
            if (parse_field_spec(set + rec_off, set_len - rec_off,
                                 &tmpl.fields[fi], &consumed) != 0) {
                emit_error(ctx, IPFIX_ERR_TRUNCATED,
                           set_offset + (uint32_t)rec_off,
                           "truncated field specifier in template");
                return -1;
            }
            rec_off += consumed;
        }

        if (store_template(ctx, &tmpl) != 0) {
            emit_error(ctx, IPFIX_ERR_TOO_MANY_TEMPLATES,
                       set_offset + (uint32_t)off,
                       "template cache full");
            return -1;
        }

        memset(&ev, 0, sizeof(ev));
        ev.type = IPFIX_EVENT_TEMPLATE;
        ev.message = ctx->last_msg;
        ev.data.tmpl = tmpl;
        emit_event(ctx, &ev);

        off = rec_off;
    }
    return 0;
}

/* ── options template set ────────────────────────────────────────────── */

static int parse_options_template_set(ipfix_ctx_t *ctx, const uint8_t *set,
                                      uint16_t set_len, uint32_t set_offset)
{
    size_t off = IPFIX_SET_HEADER_LEN;

    while (off + 6u <= set_len) {
        uint16_t tid = rd16(set + off);
        uint16_t fcount = rd16(set + off + 2);
        uint16_t scope_count = rd16(set + off + 4);
        size_t rec_off = off + 6u;
        ipfix_template_t tmpl;
        uint16_t fi;
        ipfix_event_t ev;

        if (tid < 256u && fcount != 0u) {
            break; /* padding */
        }

        memset(&tmpl, 0, sizeof(tmpl));
        tmpl.template_id = tid;
        tmpl.field_count = fcount;
        tmpl.scope_field_count = scope_count;
        tmpl.is_options = 1;

        if (fcount == 0u) {
            withdraw_template(ctx, tid);
            memset(&ev, 0, sizeof(ev));
            ev.type = IPFIX_EVENT_TEMPLATE_WITHDRAW;
            ev.message = ctx->last_msg;
            ev.data.tmpl = tmpl;
            emit_event(ctx, &ev);
            off = rec_off;
            continue;
        }

        if (scope_count == 0u || scope_count > fcount) {
            emit_error(ctx, IPFIX_ERR_BAD_TEMPLATE,
                       set_offset + (uint32_t)off,
                       "invalid options scope_field_count");
            return -1;
        }

        if (fcount > IPFIX_MAX_FIELDS_PER_TEMPLATE) {
            emit_error(ctx, IPFIX_ERR_BAD_TEMPLATE, set_offset + (uint32_t)off,
                       "options template field_count exceeds limit");
            return -1;
        }

        for (fi = 0; fi < fcount; fi++) {
            size_t consumed = 0;
            if (parse_field_spec(set + rec_off, set_len - rec_off,
                                 &tmpl.fields[fi], &consumed) != 0) {
                emit_error(ctx, IPFIX_ERR_TRUNCATED,
                           set_offset + (uint32_t)rec_off,
                           "truncated field specifier in options template");
                return -1;
            }
            if (fi < scope_count) {
                tmpl.fields[fi].is_scope = 1;
            }
            rec_off += consumed;
        }

        if (store_template(ctx, &tmpl) != 0) {
            emit_error(ctx, IPFIX_ERR_TOO_MANY_TEMPLATES,
                       set_offset + (uint32_t)off,
                       "template cache full");
            return -1;
        }

        memset(&ev, 0, sizeof(ev));
        ev.type = IPFIX_EVENT_OPTIONS_TEMPLATE;
        ev.message = ctx->last_msg;
        ev.data.tmpl = tmpl;
        emit_event(ctx, &ev);

        off = rec_off;
    }
    return 0;
}

/* ── variable-length field prefix ────────────────────────────────────── */

static int read_varlen(const uint8_t *p, size_t avail,
                       uint16_t *out_len, size_t *prefix_len)
{
    if (avail < 1u) {
        return -1;
    }
    if (p[0] < 255u) {
        *out_len = p[0];
        *prefix_len = 1u;
        return 0;
    }
    if (avail < 3u) {
        return -1;
    }
    *out_len = rd16(p + 1);
    *prefix_len = 3u;
    return 0;
}

/* ── data set ────────────────────────────────────────────────────────── */

static int parse_one_record(ipfix_ctx_t *ctx, const ipfix_template_t *tmpl,
                            const uint8_t *data, size_t avail,
                            size_t *consumed, uint16_t set_id,
                            uint32_t abs_offset)
{
    ipfix_data_record_t rec;
    size_t off = 0;
    uint16_t fi;
    ipfix_event_t ev;

    memset(&rec, 0, sizeof(rec));
    rec.template_id = tmpl->template_id;
    rec.set_id = set_id;
    rec.is_options = tmpl->is_options;

    if (tmpl->field_count > IPFIX_MAX_FIELDS_PER_RECORD) {
        emit_error(ctx, IPFIX_ERR_FIELD_OVERFLOW, abs_offset,
                   "record field_count exceeds limit");
        return -1;
    }

    for (fi = 0; fi < tmpl->field_count; fi++) {
        const ipfix_field_spec_t *spec = &tmpl->fields[fi];
        uint16_t flen;
        size_t prefix = 0;
        ipfix_field_t *field;

        if (spec->is_variable) {
            if (read_varlen(data + off, avail - off, &flen, &prefix) != 0) {
                emit_error(ctx, IPFIX_ERR_TRUNCATED, abs_offset + (uint32_t)off,
                           "truncated variable-length field");
                return -1;
            }
        } else {
            flen = spec->field_length;
        }

        if (off + prefix + flen > avail) {
            emit_error(ctx, IPFIX_ERR_TRUNCATED, abs_offset + (uint32_t)off,
                       "truncated data field");
            return -1;
        }

        field = &rec.fields[rec.field_count];
        field->element_id = spec->element_id;
        field->enterprise_number = spec->enterprise_number;
        decode_field_value(field, data + off + prefix, flen);
        rec.field_count++;

        off += prefix + flen;
    }

    fill_convenience(&rec);

    memset(&ev, 0, sizeof(ev));
    ev.type = tmpl->is_options ? IPFIX_EVENT_OPTIONS_DATA
                               : IPFIX_EVENT_DATA_RECORD;
    ev.message = ctx->last_msg;
    ev.data.record = rec;
    emit_event(ctx, &ev);

    *consumed = off;
    return 0;
}

static int parse_data_set(ipfix_ctx_t *ctx, const uint8_t *set,
                          uint16_t set_id, uint16_t set_len,
                          uint32_t set_offset)
{
    const ipfix_template_t *tmpl = find_template_const(ctx, set_id);
    size_t off = IPFIX_SET_HEADER_LEN;
    ipfix_event_t ev;

    if (!tmpl) {
        if (ctx->cfg.drop_unknown_sets) {
            return 0;
        }
        emit_error(ctx, IPFIX_ERR_UNKNOWN_TEMPLATE, set_offset,
                   "data set references unknown template");
        return 0; /* non-fatal: skip set */
    }

    while (off < set_len) {
        size_t remaining = set_len - off;
        size_t consumed = 0;
        size_t min_fixed = 0;
        uint16_t fi;

        /* Estimate minimum record size (fixed fields only). If remaining
         * is less than that, treat as padding. */
        for (fi = 0; fi < tmpl->field_count; fi++) {
            if (!tmpl->fields[fi].is_variable) {
                min_fixed += tmpl->fields[fi].field_length;
            } else {
                min_fixed += 1u; /* at least the length octet */
            }
        }
        if (remaining < min_fixed) {
            break; /* padding */
        }

        if (parse_one_record(ctx, tmpl, set + off, remaining, &consumed,
                             set_id, set_offset + (uint32_t)off) != 0) {
            return -1;
        }
        if (consumed == 0) {
            break;
        }
        off += consumed;
    }

    memset(&ev, 0, sizeof(ev));
    ev.type = IPFIX_EVENT_SET_END;
    ev.message = ctx->last_msg;
    ev.data.set_id = set_id;
    emit_event(ctx, &ev);
    return 0;
}

/* ── message parser ──────────────────────────────────────────────────── */

static int parse_message(ipfix_ctx_t *ctx, const uint8_t *msg, size_t len)
{
    uint16_t version;
    uint16_t mlen;
    size_t off;
    ipfix_event_t ev;

    if (len < IPFIX_MSG_HEADER_LEN) {
        emit_error(ctx, IPFIX_ERR_TRUNCATED, 0, "message shorter than header");
        return -1;
    }

    version = rd16(msg);
    mlen = rd16(msg + 2);

    if (version != IPFIX_PROTOCOL_VERSION) {
        emit_error(ctx, IPFIX_ERR_BAD_VERSION, 0, "unsupported IPFIX version");
        return -1;
    }
    if (mlen < IPFIX_MSG_HEADER_LEN || mlen > len) {
        emit_error(ctx, IPFIX_ERR_BAD_LENGTH, 0, "invalid message length");
        return -1;
    }
    if (mlen > ctx->cfg.max_message_size) {
        emit_error(ctx, IPFIX_ERR_BAD_LENGTH, 0, "message exceeds max_message_size");
        return -1;
    }

    ctx->last_msg.version = version;
    ctx->last_msg.length = mlen;
    ctx->last_msg.export_time = rd32(msg + 4);
    ctx->last_msg.sequence_number = rd32(msg + 8);
    ctx->last_msg.observation_domain_id = rd32(msg + 12);

    memset(&ev, 0, sizeof(ev));
    ev.type = IPFIX_EVENT_MESSAGE;
    ev.message = ctx->last_msg;
    emit_event(ctx, &ev);

    off = IPFIX_MSG_HEADER_LEN;
    while (off + IPFIX_SET_HEADER_LEN <= mlen) {
        uint16_t set_id = rd16(msg + off);
        uint16_t set_len = rd16(msg + off + 2);

        if (set_len < IPFIX_SET_HEADER_LEN || off + set_len > mlen) {
            emit_error(ctx, IPFIX_ERR_BAD_LENGTH, (uint32_t)off,
                       "invalid set length");
            return -1;
        }

        if (set_id == IPFIX_SET_TEMPLATE) {
            if (parse_template_set(ctx, msg + off, set_len, (uint32_t)off) != 0) {
                return -1;
            }
        } else if (set_id == IPFIX_SET_OPTIONS_TEMPLATE) {
            if (parse_options_template_set(ctx, msg + off, set_len,
                                           (uint32_t)off) != 0) {
                return -1;
            }
        } else if (set_id >= 256u) {
            if (parse_data_set(ctx, msg + off, set_id, set_len,
                               (uint32_t)off) != 0) {
                return -1;
            }
        } else {
            emit_error(ctx, IPFIX_ERR_BAD_SET_ID, (uint32_t)off,
                       "reserved or invalid set id");
            /* continue past set */
        }

        off += set_len;
    }

    return 0;
}

/* ── public API: config / lifecycle ──────────────────────────────────── */

ipfix_config_t ipfix_default_config(void)
{
    ipfix_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.event_queue_size = DEFAULT_QUEUE_SIZE;
    cfg.max_message_size = DEFAULT_MAX_MESSAGE;
    cfg.max_templates = DEFAULT_MAX_TEMPLATES;
    cfg.max_input_buffer = DEFAULT_MAX_INPUT;
    cfg.drop_unknown_sets = 0;
    return cfg;
}

static ipfix_ctx_t *create_internal(ipfix_role_t role, const ipfix_config_t *cfg)
{
    ipfix_ctx_t *ctx;
    ipfix_config_t c;

    if (cfg) {
        c = *cfg;
    } else {
        c = ipfix_default_config();
    }
    if (c.event_queue_size == 0) {
        c.event_queue_size = DEFAULT_QUEUE_SIZE;
    }
    if (c.max_message_size == 0) {
        c.max_message_size = DEFAULT_MAX_MESSAGE;
    }
    if (c.max_templates == 0) {
        c.max_templates = DEFAULT_MAX_TEMPLATES;
    }
    if (c.max_input_buffer == 0) {
        c.max_input_buffer = DEFAULT_MAX_INPUT;
    }

    ctx = (ipfix_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx) {
        return NULL;
    }
    ctx->role = role;
    ctx->cfg = c;
    ctx->queue_size = c.event_queue_size;
    ctx->template_cap = c.max_templates;
    ctx->input_cap = c.max_input_buffer;

    ctx->events = (ipfix_event_t *)calloc(ctx->queue_size, sizeof(ipfix_event_t));
    ctx->templates = (ipfix_template_t *)calloc(ctx->template_cap,
                                                 sizeof(ipfix_template_t));
    ctx->input_buf = (uint8_t *)malloc(ctx->input_cap);

    if (!ctx->events || !ctx->templates || !ctx->input_buf) {
        ipfix_destroy(ctx);
        return NULL;
    }
    return ctx;
}

ipfix_ctx_t *ipfix_create(void)
{
    return create_internal(IPFIX_ROLE_COLLECTOR, NULL);
}

ipfix_ctx_t *ipfix_create_role(ipfix_role_t role)
{
    return create_internal(role, NULL);
}

ipfix_ctx_t *ipfix_create_with_config(ipfix_role_t role,
                                      const ipfix_config_t *cfg)
{
    return create_internal(role, cfg);
}

void ipfix_destroy(ipfix_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    free(ctx->events);
    free(ctx->templates);
    free(ctx->input_buf);
    free(ctx);
}

int ipfix_reset(ipfix_ctx_t *ctx)
{
    if (!ctx) {
        return -1;
    }
    ctx->head = 0;
    ctx->tail = 0;
    ctx->count = 0;
    ctx->input_len = 0;
    memset(&ctx->last_msg, 0, sizeof(ctx->last_msg));
    /* templates retained */
    return 0;
}

int ipfix_clear_templates(ipfix_ctx_t *ctx)
{
    if (!ctx) {
        return -1;
    }
    ctx->template_count = 0;
    return 0;
}

/* ── feeding ─────────────────────────────────────────────────────────── */

int ipfix_feed_message(ipfix_ctx_t *ctx, const uint8_t *data, size_t len)
{
    if (!ctx || !data) {
        return -1;
    }
    if (ctx->role != IPFIX_ROLE_COLLECTOR) {
        return -1;
    }
    return parse_message(ctx, data, len);
}

int ipfix_feed_input(ipfix_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t need;

    if (!ctx || (!data && len > 0)) {
        return -1;
    }
    if (ctx->role != IPFIX_ROLE_COLLECTOR) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    /* Append to reassembly buffer. */
    if (ctx->input_len + len > ctx->input_cap) {
        emit_error(ctx, IPFIX_ERR_BUFFER_FULL, 0, "input reassembly buffer full");
        return -1;
    }
    memcpy(ctx->input_buf + ctx->input_len, data, len);
    ctx->input_len += len;

    /* Extract complete messages. */
    while (ctx->input_len >= IPFIX_MSG_HEADER_LEN) {
        uint16_t mlen = rd16(ctx->input_buf + 2);
        if (mlen < IPFIX_MSG_HEADER_LEN) {
            emit_error(ctx, IPFIX_ERR_BAD_LENGTH, 0, "message length too small");
            ctx->input_len = 0;
            return -1;
        }
        if (mlen > ctx->cfg.max_message_size) {
            emit_error(ctx, IPFIX_ERR_BAD_LENGTH, 0, "message exceeds max_message_size");
            ctx->input_len = 0;
            return -1;
        }
        if (ctx->input_len < mlen) {
            break; /* wait for more data */
        }

        if (parse_message(ctx, ctx->input_buf, mlen) != 0) {
            /* parse_message already emitted error; drop this message */
        }

        /* Shift remaining bytes. */
        need = ctx->input_len - mlen;
        if (need > 0) {
            memmove(ctx->input_buf, ctx->input_buf + mlen, need);
        }
        ctx->input_len = need;
    }
    return 0;
}

/* ── event consumption ───────────────────────────────────────────────── */

int ipfix_next_event(ipfix_ctx_t *ctx, ipfix_event_t *out)
{
    if (!ctx || !out) {
        return -1;
    }
    if (ctx->count == 0) {
        return 0;
    }
    *out = ctx->events[ctx->tail];
    ctx->tail = (ctx->tail + 1u) % ctx->queue_size;
    ctx->count--;
    return 1;
}

int ipfix_has_pending_events(const ipfix_ctx_t *ctx)
{
    if (!ctx) {
        return 0;
    }
    return ctx->count > 0 ? 1 : 0;
}

uint32_t ipfix_event_count(const ipfix_ctx_t *ctx)
{
    if (!ctx) {
        return 0;
    }
    return ctx->count;
}

uint64_t ipfix_dropped_count(const ipfix_ctx_t *ctx)
{
    if (!ctx) {
        return 0;
    }
    return ctx->dropped;
}

/* ── template inspection ─────────────────────────────────────────────── */

uint32_t ipfix_template_count(const ipfix_ctx_t *ctx)
{
    if (!ctx) {
        return 0;
    }
    return ctx->template_count;
}

int ipfix_get_template(const ipfix_ctx_t *ctx, uint16_t template_id,
                       ipfix_template_t *out)
{
    const ipfix_template_t *t;
    if (!ctx || !out) {
        return 0;
    }
    t = find_template_const(ctx, template_id);
    if (!t) {
        return 0;
    }
    *out = *t;
    return 1;
}

/* ── field helpers ───────────────────────────────────────────────────── */

const ipfix_field_t *ipfix_record_find_field(const ipfix_data_record_t *rec,
                                              uint16_t element_id)
{
    return ipfix_record_find_enterprise_field(rec, 0, element_id);
}

const ipfix_field_t *ipfix_record_find_enterprise_field(
    const ipfix_data_record_t *rec,
    uint32_t enterprise_number,
    uint16_t element_id)
{
    uint16_t i;
    if (!rec) {
        return NULL;
    }
    for (i = 0; i < rec->field_count; i++) {
        if (rec->fields[i].element_id == element_id &&
            rec->fields[i].enterprise_number == enterprise_number) {
            return &rec->fields[i];
        }
    }
    return NULL;
}

const char *ipfix_ie_name(uint16_t element_id)
{
    switch (element_id) {
    case 1:   return "octetDeltaCount";
    case 2:   return "packetDeltaCount";
    case 3:   return "deltaFlowCount";
    case 4:   return "protocolIdentifier";
    case 5:   return "ipClassOfService";
    case 6:   return "tcpControlBits";
    case 7:   return "sourceTransportPort";
    case 8:   return "sourceIPv4Address";
    case 9:   return "sourceIPv4PrefixLength";
    case 10:  return "ingressInterface";
    case 11:  return "destinationTransportPort";
    case 12:  return "destinationIPv4Address";
    case 13:  return "destinationIPv4PrefixLength";
    case 14:  return "egressInterface";
    case 15:  return "ipNextHopIPv4Address";
    case 16:  return "bgpSourceAsNumber";
    case 17:  return "bgpDestinationAsNumber";
    case 18:  return "bgpNextHopIPv4Address";
    case 21:  return "flowEndSysUpTime";
    case 22:  return "flowStartSysUpTime";
    case 27:  return "sourceIPv6Address";
    case 28:  return "destinationIPv6Address";
    case 56:  return "sourceMacAddress";
    case 80:  return "destinationMacAddress";
    case 85:  return "octetTotalCount";
    case 86:  return "packetTotalCount";
    case 130: return "exporterIPv4Address";
    case 132: return "droppedOctetDeltaCount";
    case 133: return "droppedPacketDeltaCount";
    case 136: return "flowEndReason";
    case 148: return "flowId";
    case 150: return "flowStartSeconds";
    case 151: return "flowEndSeconds";
    case 152: return "flowStartMilliseconds";
    case 153: return "flowEndMilliseconds";
    case 160: return "systemInitTimeMilliseconds";
    case 161: return "flowDurationMilliseconds";
    default:  return NULL;
    }
}

const char *ipfix_event_type_name(ipfix_event_type_t type)
{
    switch (type) {
    case IPFIX_EVENT_MESSAGE:           return "MESSAGE";
    case IPFIX_EVENT_TEMPLATE:          return "TEMPLATE";
    case IPFIX_EVENT_OPTIONS_TEMPLATE:  return "OPTIONS_TEMPLATE";
    case IPFIX_EVENT_DATA_RECORD:       return "DATA_RECORD";
    case IPFIX_EVENT_OPTIONS_DATA:      return "OPTIONS_DATA";
    case IPFIX_EVENT_SET_END:           return "SET_END";
    case IPFIX_EVENT_ERROR:             return "ERROR";
    case IPFIX_EVENT_QUEUE_OVERFLOW:    return "QUEUE_OVERFLOW";
    case IPFIX_EVENT_TEMPLATE_WITHDRAW: return "TEMPLATE_WITHDRAW";
    default:                            return "UNKNOWN";
    }
}

const char *ipfix_error_name(ipfix_error_code_t code)
{
    switch (code) {
    case IPFIX_ERR_NONE:               return "NONE";
    case IPFIX_ERR_BAD_VERSION:        return "BAD_VERSION";
    case IPFIX_ERR_TRUNCATED:          return "TRUNCATED";
    case IPFIX_ERR_BAD_LENGTH:         return "BAD_LENGTH";
    case IPFIX_ERR_UNKNOWN_TEMPLATE:   return "UNKNOWN_TEMPLATE";
    case IPFIX_ERR_BAD_TEMPLATE:       return "BAD_TEMPLATE";
    case IPFIX_ERR_BAD_SET_ID:         return "BAD_SET_ID";
    case IPFIX_ERR_FIELD_OVERFLOW:     return "FIELD_OVERFLOW";
    case IPFIX_ERR_BUFFER_FULL:        return "BUFFER_FULL";
    case IPFIX_ERR_TOO_MANY_TEMPLATES: return "TOO_MANY_TEMPLATES";
    case IPFIX_ERR_INVALID_STATE:      return "INVALID_STATE";
    default:                           return "UNKNOWN";
    }
}

char *ipfix_format_ipv4(uint32_t addr, char *buf, size_t buflen)
{
    if (!buf || buflen < 16u) {
        return buf;
    }
    snprintf(buf, buflen, "%u.%u.%u.%u",
             (unsigned)((addr >> 24) & 0xFFu),
             (unsigned)((addr >> 16) & 0xFFu),
             (unsigned)((addr >> 8) & 0xFFu),
             (unsigned)(addr & 0xFFu));
    return buf;
}

char *ipfix_format_ipv6(const uint8_t addr[IPFIX_IPV6_ADDR_LEN],
                        char *buf, size_t buflen)
{
    if (!buf || buflen < 40u || !addr) {
        return buf;
    }
    snprintf(buf, buflen,
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             addr[0], addr[1], addr[2], addr[3],
             addr[4], addr[5], addr[6], addr[7],
             addr[8], addr[9], addr[10], addr[11],
             addr[12], addr[13], addr[14], addr[15]);
    return buf;
}
