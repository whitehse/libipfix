# Fuzzing libipfix

Requires **clang** with libFuzzer.

```bash
CC=clang cmake -B build-fuzz -S . -DBUILD_FUZZ=ON
cmake --build build-fuzz --target ipfix_fuzz

# Seed + evolve corpus
mkdir -p fuzz/corpus fuzz/artifacts
cp fuzz/seed_corpus/* fuzz/corpus/
./build-fuzz/ipfix_fuzz fuzz/corpus \
  -artifact_prefix=fuzz/artifacts/ \
  -dict=fuzz/ipfix.dict \
  -max_total_time=300 \
  -max_len=8192 \
  -print_final_stats=1
```

The harness feeds both `ipfix_feed_input` (chunked) and `ipfix_feed_message`,
drains events, and exercises field/template helpers under ASan + UBSan.
