# CBOR allocation limits

## Background

`cbor_load()` (libcbor) pre-allocates storage for definite-length CBOR
arrays and maps sized by the element count declared in the message header,
*before* reading any element data. The only check applied to that count is
an integer-overflow check
([`_cbor_safe_to_multiply`](https://github.com/PJK/libcbor/blob/master/src/cbor/internal/memory_utils.c)) -
there is no sanity bound relative to the size of the input itself.

As a result, a handful of bytes can cause `cbor_load()` to attempt an
allocation of an arbitrary size. This was reported upstream as
[PJK/libcbor#418](https://github.com/PJK/libcbor/issues/418) (a 5-byte input
triggering a ~2.3GB allocation, and a 9-byte input triggering a ~128GB
allocation) and closed as "won't fix": libcbor considers this the
responsibility of the consumer.
[PJK/libcbor#422](https://github.com/PJK/libcbor/pull/422) (merged in
0.14.0) documents the recommended mitigation: install a capping allocator
via `cbor_set_allocs()` (see `examples/capped_alloc.c` in libcbor) so that
`cbor_load()` fails with `CBOR_ERR_MEMERROR` instead of making an oversized
allocation.

In *libfido2*, `cbor_load()` is reachable from a FIDO authenticator's CTAP
responses (`src/assert.c`, `src/cbor.c`, `src/cred.c`, `src/credman.c`,
`src/largeblob.c`, `src/winhello.c`). A malicious or malfunctioning
authenticator could therefore use a tiny CBOR message to make a host
process attempt a multi-gigabyte (or larger) allocation, regardless of the
small `FIDO_MAXMSG`/`FIDO_MAXMSG_CRED` limits applied to the raw transport
buffer - those limits bound the number of *bytes read*, not the element
count *declared* inside those bytes.

## Mitigation

`fido_init()` (`src/dev.c`) calls `fido_init_cbor_allocs()`
(`src/cbor_alloc.c`), which installs a capping allocator via
`cbor_set_allocs()`. The allocator tracks the total size of live libcbor
allocations and rejects any allocation that would push the total above
`FIDO_CBOR_MAX_ALLOC` (`src/fido/param.h`, 64MB by default). Once the budget
is exhausted, `cbor_load()` returns `NULL` with
`result.error.code == CBOR_ERR_MEMERROR`, which every `cbor_load()` caller
in *libfido2* already treats as an ordinary decode failure.

64MB is well above `FIDO_MAXMSG` (2048 bytes), `FIDO_MAXMSG_CRED` (4096
bytes), and any realistic `largeBlob` array, while remaining far below a
level that could exhaust process memory or trigger the OOM killer.
`FIDO_CBOR_MAX_ALLOC` may be overridden at build time for embedded targets
with tighter memory budgets.

Because `cbor_set_allocs()` configures a single, process-wide set of
function pointers in libcbor, and `fido_init()` is documented to be called
once per thread (see `fido_init(3)`), the allocation-size counter in
`src/cbor_alloc.c` is thread-local (`TLS`). This follows the per-thread
budget alternative suggested in PJK/libcbor#422, and assumes - as is the
case throughout *libfido2* - that a `cbor_item_t` allocated by `cbor_load()`
in one thread is not freed from another.

A regression test for this is in `regress/dev.c`
(`cbor_alloc_cap()`): it feeds `cbor_load()` a 9-byte CBOR array header
declaring 268M elements (which would otherwise provoke a ~2GB allocation)
and asserts that it is rejected with `CBOR_ERR_MEMERROR`.

## Relationship to fuzz/README's libcbor patch

`fuzz/README` documents an unrelated, fuzzing-only patch to libcbor that
caps `_cbor_alloc_multiple` at 1000 items. That patch exists to keep
ASAN/MSAN/UBSAN memory usage bounded *during fuzzing* and is far too
restrictive for production use - it would reject legitimate messages with
more than 1000 array/map elements. It is applied to a local libcbor build
used only by the fuzzing harness and does not protect applications linking
against a normal libcbor.

The mitigation described above is independent of that patch: it ships in
*libfido2* itself, applies to every build (not just fuzzing builds), and
uses a memory budget rather than an element-count limit so it does not
reject legitimate large messages.
