/**
 * @file ipfix.h
 * @brief Pure C IPFIX (IP Flow Information Export) receiver.
 *
 * Parses IPFIX messages (RFC 7011) from caller-supplied byte buffers.
 * No syscalls, no callbacks, no blocking. Socket I/O and timers are
 * the caller's responsibility (io_uring, epoll, libuv, etc.).
 *
 * Copyright (c) 2026 libipfix contributors — MIT licence
 */
#ifndef IPFIX_H
#define IPFIX_H

#include <stddef.h>
#include <stdint.h>

#include "ipfix_enterprise_calix.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Library version components. */
#define IPFIX_VERSION_MAJOR 0
#define IPFIX_VERSION_MINOR 1
#define IPFIX_VERSION_PATCH 0

/** IPFIX protocol version number (RFC 7011). */
#define IPFIX_PROTOCOL_VERSION 10

/* ── limits ──────────────────────────────────────────────────────────── */

#define IPFIX_MAX_FIELDS_PER_TEMPLATE  64
#define IPFIX_MAX_FIELDS_PER_RECORD    64
#define IPFIX_MAX_FIELD_VALUE_LEN      256
#define IPFIX_MAX_ERROR_MSG_LEN        256
#define IPFIX_IPV6_ADDR_LEN            16

/* ── configuration ───────────────────────────────────────────────────── */

/**
 * Configuration passed to ipfix_create_with_config().
 * Zero-initialize and set only the fields you care about; defaults
 * fill in the rest via ipfix_default_config().
 */
typedef struct {
    uint32_t event_queue_size;    /**< Ring-buffer capacity (default 256). */
    uint32_t max_message_size;    /**< Max IPFIX message size (default 64 KiB). */
    uint32_t max_templates;       /**< Template cache capacity (default 256). */
    uint32_t max_input_buffer;    /**< Stream reassembly buffer (default 256 KiB). */
    int      drop_unknown_sets;   /**< 1 = ignore data sets without a template. */
} ipfix_config_t;

/** Return the default configuration. */
ipfix_config_t ipfix_default_config(void);

/* ── role ────────────────────────────────────────────────────────────── */

/** Operating role. */
typedef enum {
    IPFIX_ROLE_COLLECTOR = 0,  /**< Receive and parse IPFIX (default). */
    IPFIX_ROLE_EXPORTER  = 1   /**< Reserved for future encoding. */
} ipfix_role_t;

/* ── information element identifiers (common IANA IEs) ─────────────── */

typedef enum {
    IPFIX_IE_octetDeltaCount            = 1,
    IPFIX_IE_packetDeltaCount           = 2,
    IPFIX_IE_deltaFlowCount             = 3,
    IPFIX_IE_protocolIdentifier         = 4,
    IPFIX_IE_ipClassOfService           = 5,
    IPFIX_IE_tcpControlBits             = 6,
    IPFIX_IE_sourceTransportPort        = 7,
    IPFIX_IE_sourceIPv4Address          = 8,
    IPFIX_IE_sourceIPv4PrefixLength     = 9,
    IPFIX_IE_ingressInterface           = 10,
    IPFIX_IE_destinationTransportPort   = 11,
    IPFIX_IE_destinationIPv4Address     = 12,
    IPFIX_IE_destinationIPv4PrefixLength = 13,
    IPFIX_IE_egressInterface            = 14,
    IPFIX_IE_ipNextHopIPv4Address       = 15,
    IPFIX_IE_bgpSourceAsNumber          = 16,
    IPFIX_IE_bgpDestinationAsNumber     = 17,
    IPFIX_IE_bgpNextHopIPv4Address      = 18,
    IPFIX_IE_flowEndSysUpTime           = 21,
    IPFIX_IE_flowStartSysUpTime         = 22,
    IPFIX_IE_sourceIPv6Address          = 27,
    IPFIX_IE_destinationIPv6Address     = 28,
    IPFIX_IE_sourceIPv6PrefixLength     = 29,
    IPFIX_IE_destinationIPv6PrefixLength = 30,
    IPFIX_IE_flowLabelIPv6              = 31,
    IPFIX_IE_icmpTypeCodeIPv4           = 32,
    IPFIX_IE_samplingInterval           = 34,
    IPFIX_IE_sourceMacAddress           = 56,
    IPFIX_IE_destinationMacAddress      = 80,
    IPFIX_IE_octetTotalCount            = 85,
    IPFIX_IE_packetTotalCount           = 86,
    IPFIX_IE_forwardingStatus           = 89,
    IPFIX_IE_applicationDescription     = 94,
    IPFIX_IE_applicationId              = 95,
    IPFIX_IE_exporterIPv4Address        = 130,
    IPFIX_IE_exporterIPv6Address        = 131,
    IPFIX_IE_droppedOctetDeltaCount     = 132,
    IPFIX_IE_droppedPacketDeltaCount    = 133,
    IPFIX_IE_flowEndReason              = 136,
    IPFIX_IE_observationPointId         = 138,
    IPFIX_IE_icmpTypeCodeIPv6           = 139,
    IPFIX_IE_flowId                     = 148,
    IPFIX_IE_observationDomainId        = 149,
    IPFIX_IE_flowStartSeconds           = 150,
    IPFIX_IE_flowEndSeconds             = 151,
    IPFIX_IE_flowStartMilliseconds      = 152,
    IPFIX_IE_flowEndMilliseconds        = 153,
    IPFIX_IE_flowStartMicroseconds      = 154,
    IPFIX_IE_flowEndMicroseconds        = 155,
    IPFIX_IE_flowStartNanoseconds       = 156,
    IPFIX_IE_flowEndNanoseconds         = 157,
    IPFIX_IE_flowStartDeltaMicroseconds = 158,
    IPFIX_IE_flowEndDeltaMicroseconds   = 159,
    IPFIX_IE_systemInitTimeMilliseconds = 160,
    IPFIX_IE_flowDurationMilliseconds   = 161,
    IPFIX_IE_flowDurationMicroseconds   = 162,
    IPFIX_IE_originalFlowsPresent       = 163,
    IPFIX_IE_originalFlowsInitiated     = 164,
    IPFIX_IE_originalFlowsCompleted     = 165,
    IPFIX_IE_selectorId                 = 302,
    IPFIX_IE_selectorAlgorithm          = 304,
    IPFIX_IE_samplingPacketInterval     = 305,
    IPFIX_IE_samplingPacketSpace        = 306
} ipfix_ie_id_t;

/* ── abstract IE data types (registry / decoding hints) ──────────────── */

/**
 * Semantic data type of an Information Element from a static registry.
 * Used to classify enterprise (and optionally IANA) fields beyond wire length.
 */
typedef enum {
    IPFIX_IE_DT_UNKNOWN    = 0,  /**< Not in registry; decoder uses heuristics. */
    IPFIX_IE_DT_UNSIGNED   = 1,  /**< Unsigned integer (uint8..uint64). */
    IPFIX_IE_DT_SIGNED     = 2,  /**< Signed integer (int8..int64). */
    IPFIX_IE_DT_FLOAT      = 3,  /**< IEEE 754 binary32/binary64. */
    IPFIX_IE_DT_STRING     = 4,  /**< Character string (UTF-8 / ASCII). */
    IPFIX_IE_DT_OCTETARRAY = 5   /**< Opaque octet array. */
} ipfix_ie_datatype_t;

/* ── field value kinds ───────────────────────────────────────────────── */

/** How a decoded field value is represented. */
typedef enum {
    IPFIX_VALUE_RAW      = 0,  /**< Opaque bytes in raw[]. */
    IPFIX_VALUE_UINT     = 1,  /**< Unsigned integer in u64. */
    IPFIX_VALUE_IPV4     = 2,  /**< IPv4 address in ipv4 (host order). */
    IPFIX_VALUE_IPV6     = 3,  /**< IPv6 address in ipv6[]. */
    IPFIX_VALUE_MAC      = 4,  /**< 6-byte MAC in mac[]. */
    IPFIX_VALUE_STRING   = 5,  /**< NUL-terminated string in raw[]. */
    IPFIX_VALUE_INT      = 6,  /**< Signed integer in i64 (sign-extended). */
    IPFIX_VALUE_FLOAT    = 7   /**< IEEE 754 value in f64 (float32 promoted). */
} ipfix_value_kind_t;

/** A single field specifier from a template. */
typedef struct {
    uint16_t element_id;       /**< IE id (low 15 bits; enterprise bit stripped). */
    uint16_t field_length;     /**< Fixed length, or 65535 for variable. */
    uint32_t enterprise_number;/**< 0 for IANA IEs. */
    int      is_variable;      /**< 1 if field_length was 65535. */
    int      is_scope;         /**< 1 if this is a scope field (options). */
} ipfix_field_spec_t;

/** A decoded field value from a data record. */
typedef struct {
    uint16_t           element_id;
    uint32_t           enterprise_number;
    uint16_t           length;           /**< Actual value length in bytes. */
    ipfix_value_kind_t kind;
    union {
        uint64_t u64;
        int64_t  i64;                    /**< Sign-extended signed integer. */
        double   f64;                    /**< Float32 promoted or float64. */
        uint32_t ipv4;                   /**< Host-byte-order IPv4. */
        uint8_t  ipv6[IPFIX_IPV6_ADDR_LEN];
        uint8_t  mac[6];
        uint8_t  raw[IPFIX_MAX_FIELD_VALUE_LEN];
    } v;
} ipfix_field_t;

/** A learned template (or options template). */
typedef struct {
    uint16_t          template_id;       /**< 256–65535. */
    uint16_t          field_count;
    uint16_t          scope_field_count; /**< Non-zero for options templates. */
    int               is_options;
    ipfix_field_spec_t fields[IPFIX_MAX_FIELDS_PER_TEMPLATE];
} ipfix_template_t;

/* ── message header (decoded) ────────────────────────────────────────── */

typedef struct {
    uint16_t version;            /**< Must be 10. */
    uint16_t length;             /**< Total message length including header. */
    uint32_t export_time;        /**< Seconds since epoch. */
    uint32_t sequence_number;    /**< Exporting Process sequence. */
    uint32_t observation_domain_id;
} ipfix_message_header_t;

/* ── event types ─────────────────────────────────────────────────────── */

typedef enum {
    IPFIX_EVENT_MESSAGE          = 0,  /**< Message header parsed. */
    IPFIX_EVENT_TEMPLATE         = 1,  /**< Template Set record learned. */
    IPFIX_EVENT_OPTIONS_TEMPLATE = 2,  /**< Options Template learned. */
    IPFIX_EVENT_DATA_RECORD      = 3,  /**< Data Set record decoded. */
    IPFIX_EVENT_OPTIONS_DATA     = 4,  /**< Options Data Set record decoded. */
    IPFIX_EVENT_SET_END          = 5,  /**< Finished a set (informational). */
    IPFIX_EVENT_ERROR            = 6,  /**< Parse or protocol error. */
    IPFIX_EVENT_QUEUE_OVERFLOW   = 7,  /**< Event ring buffer overflowed. */
    IPFIX_EVENT_TEMPLATE_WITHDRAW= 8   /**< Template withdrawn (field_count=0). */
} ipfix_event_type_t;

/** Error codes carried by IPFIX_EVENT_ERROR. */
typedef enum {
    IPFIX_ERR_NONE               = 0,
    IPFIX_ERR_BAD_VERSION        = 1,
    IPFIX_ERR_TRUNCATED          = 2,
    IPFIX_ERR_BAD_LENGTH         = 3,
    IPFIX_ERR_UNKNOWN_TEMPLATE   = 4,
    IPFIX_ERR_BAD_TEMPLATE       = 5,
    IPFIX_ERR_BAD_SET_ID         = 6,
    IPFIX_ERR_FIELD_OVERFLOW     = 7,
    IPFIX_ERR_BUFFER_FULL        = 8,
    IPFIX_ERR_TOO_MANY_TEMPLATES = 9,
    IPFIX_ERR_INVALID_STATE      = 10
} ipfix_error_code_t;

typedef struct {
    ipfix_error_code_t code;
    char               message[IPFIX_MAX_ERROR_MSG_LEN];
    uint32_t           offset;   /**< Byte offset within current message. */
} ipfix_error_t;

/** Decoded data / options data record. */
typedef struct {
    uint16_t      template_id;
    uint16_t      set_id;
    uint16_t      field_count;
    int           is_options;
    ipfix_field_t fields[IPFIX_MAX_FIELDS_PER_RECORD];
    /* Convenience extracts for common IEs (valid if the field is present). */
    int           has_src_ipv4;
    int           has_dst_ipv4;
    int           has_src_port;
    int           has_dst_port;
    int           has_protocol;
    int           has_octet_delta;
    int           has_packet_delta;
    int           has_flow_start_ms;
    int           has_flow_end_ms;
    uint32_t      src_ipv4;
    uint32_t      dst_ipv4;
    uint16_t      src_port;
    uint16_t      dst_port;
    uint8_t       protocol;
    uint64_t      octet_delta;
    uint64_t      packet_delta;
    uint64_t      flow_start_ms;
    uint64_t      flow_end_ms;
} ipfix_data_record_t;

/** An event dequeued from the receiver. */
typedef struct {
    ipfix_event_type_t type;
    ipfix_message_header_t message; /**< Filled for most event types. */
    union {
        ipfix_template_t    tmpl;   /**< TEMPLATE / OPTIONS_TEMPLATE / WITHDRAW. */
        ipfix_data_record_t record; /**< DATA_RECORD / OPTIONS_DATA. */
        ipfix_error_t       error;  /**< ERROR. */
        uint16_t            set_id; /**< SET_END. */
    } data;
} ipfix_event_t;

/* ── opaque handle ───────────────────────────────────────────────────── */

typedef struct ipfix_ctx ipfix_ctx_t;

/* ── lifecycle ───────────────────────────────────────────────────────── */

/** Create a collector context with default config. NULL on failure. */
ipfix_ctx_t *ipfix_create(void);

/** Create with explicit role (collector recommended). NULL on failure. */
ipfix_ctx_t *ipfix_create_role(ipfix_role_t role);

/** Create with role and config. NULL on failure. */
ipfix_ctx_t *ipfix_create_with_config(ipfix_role_t role,
                                       const ipfix_config_t *cfg);

/** Destroy and free all resources. Safe to call with NULL. */
void ipfix_destroy(ipfix_ctx_t *ctx);

/**
 * Reset parse state and event queue for reuse without reallocation.
 * Template cache is retained (call ipfix_clear_templates to drop it).
 * Returns 0 on success, negative on error.
 */
int ipfix_reset(ipfix_ctx_t *ctx);

/** Drop all learned templates. Returns 0 on success. */
int ipfix_clear_templates(ipfix_ctx_t *ctx);

/* ── feeding ─────────────────────────────────────────────────────────── */

/**
 * Feed a chunk of IPFIX wire data.
 *
 * For UDP: pass one complete datagram (one or more IPFIX messages).
 * For TCP / streaming: pass arbitrary chunks; the library reassembles
 * complete messages using the Length field in the message header.
 *
 * Returns 0 on success, negative on error (buffer full, etc.).
 * Parse events are enqueued for consumption via ipfix_next_event().
 */
int ipfix_feed_input(ipfix_ctx_t *ctx, const uint8_t *data, size_t len);

/**
 * Feed a complete single IPFIX message (no stream reassembly).
 * Useful when the transport already frames messages (e.g. UDP).
 * Returns 0 on success, negative on error.
 */
int ipfix_feed_message(ipfix_ctx_t *ctx, const uint8_t *data, size_t len);

/* ── event consumption ───────────────────────────────────────────────── */

/**
 * Dequeue the next event.
 * Returns 1 if an event was written to *out, 0 if the queue is empty,
 * negative on error.
 */
int ipfix_next_event(ipfix_ctx_t *ctx, ipfix_event_t *out);

/** Non-zero if events are available. */
int ipfix_has_pending_events(const ipfix_ctx_t *ctx);

/** Number of events currently in the queue. */
uint32_t ipfix_event_count(const ipfix_ctx_t *ctx);

/** Number of events dropped due to ring-buffer overflow. */
uint64_t ipfix_dropped_count(const ipfix_ctx_t *ctx);

/* ── template inspection ─────────────────────────────────────────────── */

/** Number of templates currently cached. */
uint32_t ipfix_template_count(const ipfix_ctx_t *ctx);

/**
 * Look up a template by ID.
 * Returns 1 and fills *out on success, 0 if not found.
 */
int ipfix_get_template(const ipfix_ctx_t *ctx, uint16_t template_id,
                       ipfix_template_t *out);

/* ── field helpers ───────────────────────────────────────────────────── */

/**
 * Find a field by IANA element ID in a data record (enterprise 0).
 * Returns pointer into record->fields, or NULL if not present.
 */
const ipfix_field_t *ipfix_record_find_field(const ipfix_data_record_t *rec,
                                              uint16_t element_id);

/**
 * Find a field by enterprise number + element ID.
 * Returns pointer into record->fields, or NULL if not present.
 */
const ipfix_field_t *ipfix_record_find_enterprise_field(
    const ipfix_data_record_t *rec,
    uint32_t enterprise_number,
    uint16_t element_id);

/** Human-readable name for a well-known IANA IE, or NULL if unknown. */
const char *ipfix_ie_name(uint16_t element_id);

/**
 * Human-readable name for an enterprise IE, or NULL if unknown.
 * For enterprise_number 0, delegates to ipfix_ie_name().
 * Built-in registries currently include Calix (IPFIX_PEN_CALIX).
 */
const char *ipfix_enterprise_ie_name(uint32_t enterprise_number,
                                     uint16_t element_id);

/**
 * Registered abstract data type for an IE, or IPFIX_IE_DT_UNKNOWN.
 * enterprise_number 0 returns UNKNOWN (IANA types use value-kind heuristics).
 */
ipfix_ie_datatype_t ipfix_enterprise_ie_datatype(uint32_t enterprise_number,
                                                  uint16_t element_id);

/** Human-readable name for an event type. */
const char *ipfix_event_type_name(ipfix_event_type_t type);

/** Human-readable name for an error code. */
const char *ipfix_error_name(ipfix_error_code_t code);

/**
 * Format an IPv4 address (host order) into buf as dotted-quad.
 * Returns buf. buf must be at least 16 bytes.
 */
char *ipfix_format_ipv4(uint32_t addr, char *buf, size_t buflen);

/**
 * Format an IPv6 address into buf (compact hex).
 * Returns buf. buf must be at least 40 bytes.
 */
char *ipfix_format_ipv6(const uint8_t addr[IPFIX_IPV6_ADDR_LEN],
                        char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* IPFIX_H */
