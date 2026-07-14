# libipfix

Pure C **IPFIX receiver** (RFC 7011): template cache, data-record decoding, pull-based events.

- **Syscall-free** — no sockets, files, or timers; caller supplies wire bytes
- **Callback-free** — `ipfix_next_event()` ring buffer
- **C11 / CMake** — static library, MIT licensed

## Build

```bash
cmake -B build -S .
cmake --build build
ctest --test-dir build
./build/ipfix_example
```

## Minimal usage

```c
#include <ipfix.h>

ipfix_ctx_t *ctx = ipfix_create();
ipfix_feed_message(ctx, udp_payload, n);

ipfix_event_t ev;
while (ipfix_next_event(ctx, &ev) == 1) {
    if (ev.type == IPFIX_EVENT_DATA_RECORD && ev.data.record.has_src_ipv4) {
        char s[16], d[16];
        ipfix_format_ipv4(ev.data.record.src_ipv4, s, sizeof s);
        ipfix_format_ipv4(ev.data.record.dst_ipv4, d, sizeof d);
        /* s:src_port -> d:dst_port */
    }
}
ipfix_destroy(ctx);
```

## Documentation

| Doc | Contents |
|-----|----------|
| [AGENTS.md](AGENTS.md) | Agent entry point, directives, ADR index |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Codemap, data flow, invariants |
| [docs/DOMAIN.md](docs/DOMAIN.md) | IPFIX domain knowledge |
| [docs/decisions/](docs/decisions/) | Architecture Decision Records |

## License

MIT — see [LICENSE](LICENSE).
