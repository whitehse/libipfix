/**
 * @file ipfix_fuzz.c
 * @brief libFuzzer harness for libipfix.
 */

#include "ipfix.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ipfix_ctx_t *ctx = ipfix_create();
    ipfix_event_t ev;

    if (!ctx) {
        return 0;
    }

    /* Exercise both entry points. */
    if (size > 0) {
        (void)ipfix_feed_input(ctx, data, size);
        while (ipfix_next_event(ctx, &ev) == 1) {
            /* drain */
        }
        (void)ipfix_reset(ctx);
        (void)ipfix_feed_message(ctx, data, size);
        while (ipfix_next_event(ctx, &ev) == 1) {
            /* drain */
        }
    }

    ipfix_destroy(ctx);
    return 0;
}
