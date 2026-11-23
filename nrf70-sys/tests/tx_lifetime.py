"""Test production TX buffer ownership/counters against synchronous and queued FMAC.

Run: python3 nrf70-sys/tests/tx_lifetime.py
Uses ASan/UBSan; no radio, firmware, or credentials are needed.
"""

import os
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
source = (root / "src/facade.c").read_text()


def function(name):
    match = re.search(r"^(?:static )?[^\n{};]*\b" + name + r"\([^;{}]*\)\s*\{", source, re.M)
    assert match, name
    start = match.start()
    pos = match.end()
    depth = 1
    while depth:
        depth += (source[pos] == "{") - (source[pos] == "}")
        pos += 1
    return source[start:pos] + "\n"


PRELUDE = r"""
#include "nrf70_facade.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define mem_free free
#define nrf70_os_memcpy memcpy
#define TX_HEADROOM 64
#define CONN_IDLE 0
#define CONN_AUTHORIZED 1
static int initialized = 1, linked = 1, callbacks_enabled = 1;
static uint32_t generation = 3;
static struct { int secured, state; } conn;
static struct nrf70_facade_stats counters;
static struct nrf70_facade_event events[16];
static unsigned event_count;
static void enqueue_event(const struct nrf70_facade_event *e, int terminal) {
    (void)terminal;
    assert(event_count < 16);
    events[event_count++] = *e;
}
static void *try_alloc(size_t n, uint8_t zeroed) { return zeroed ? calloc(1, n) : malloc(n); }
static void fatal(int32_t reason, const char *msg) { (void)reason; (void)msg; abort(); }
static void *rpu_ctx(void) { return NULL; }
static unsigned char vif_idx(void) { return 0; }
enum nrf_wifi_status { NRF_WIFI_STATUS_FAIL, NRF_WIFI_STATUS_SUCCESS };
static enum nrf_wifi_status nrf_wifi_fmac_start_xmit(void *, unsigned char, void *);
"""

TEST = r"""
static int mode;
static struct nbuf *pending;
static enum nrf_wifi_status nrf_wifi_fmac_start_xmit(void *ctx, unsigned char vif, void *p) {
    (void)ctx; (void)vif;
    if (mode == 1) { pending = p; return NRF_WIFI_STATUS_SUCCESS; }
    if (pending) { nbuf_free(pending); pending = NULL; }
    unsigned before = event_count;
    nbuf_free(p);
    /* The current packet's result must not be guessed in its destructor. */
    assert(event_count == before);
    return mode == 2 ? NRF_WIFI_STATUS_FAIL : NRF_WIFI_STATUS_SUCCESS;
}
int main(void) {
    const uint8_t frame[64] = {0};
    /* Synchronous successful copy/release is NOT a failed TX. */
    assert(nrf70_facade_tx(10, frame, sizeof(frame)) == 0);
    assert(event_count == 1 && events[0].token == 10 && events[0].status == 0);
    assert(counters.tx_completed == 1 && counters.tx_failed == 0);
    assert(counters.nbuf_in_use == 0);
    /* Queued packets complete later. */
    mode = 1;
    assert(nrf70_facade_tx(11, frame, sizeof(frame)) == 0);
    assert(event_count == 1 && counters.nbuf_in_use == 1);
    nbuf_free(pending); pending = NULL;
    assert(event_count == 2 && events[1].token == 11 && events[1].status == 0);
    /* Synchronous failed submission produces one failure. */
    mode = 2;
    assert(nrf70_facade_tx(12, frame, sizeof(frame)) == NRF70_FACADE_QUEUE_FULL);
    assert(event_count == 3 && events[2].token == 12 && events[2].status == NRF70_FACADE_IO);
    assert(counters.tx_completed == 2 && counters.tx_failed == 1);
    /* A different queued packet released during a failing submission must
       not inherit the new packet's error or defer its event to that token. */
    mode = 1;
    assert(nrf70_facade_tx(13, frame, sizeof(frame)) == 0);
    mode = 2;
    assert(nrf70_facade_tx(14, frame, sizeof(frame)) == NRF70_FACADE_QUEUE_FULL);
    assert(event_count == 5);
    assert(events[3].token == 13 && events[3].status == 0);
    assert(events[4].token == 14 && events[4].status == NRF70_FACADE_IO);
    assert(counters.tx_completed == 3 && counters.tx_failed == 2);
    assert(counters.nbuf_in_use == 0 && !tx_in_call && !tx_freed_in_call);
    /* Teardown suppresses callbacks; RX frees never create TX events. */
    mode = 1;
    assert(nrf70_facade_tx(15, frame, sizeof(frame)) == 0);
    callbacks_enabled = 0;
    nbuf_free(pending); pending = NULL;
    nbuf_free(nbuf_alloc(64));
    nbuf_free(NULL);
    assert(event_count == 5 && counters.nbuf_in_use == 0);
    puts("TX lifetime: synchronous success/failure, queued release, interleaving and teardown pass");
}
"""

nbuf = re.search(r"^struct nbuf \{.*?\};", source, re.M | re.S).group(0)
code = PRELUDE + nbuf + "\nstatic struct nbuf *tx_in_call;\nstatic uint8_t tx_freed_in_call;\n"
for name in ("nbuf_try_alloc", "nbuf_alloc", "tx_complete", "nbuf_free", "nbuf_res", "nbuf_put", "nrf70_facade_tx"):
    code += function(name)

with tempfile.TemporaryDirectory() as directory:
    c = Path(directory) / "tx.c"
    binary = Path(directory) / "tx"
    c.write_text(code + TEST)
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-iquote", str(root / "include"),
                    str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
