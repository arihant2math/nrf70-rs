"""Regression test for the production IRQ-fetch patch (not facade_mock.c).

Build the firmware first, then pass its generated hal_interrupt_bounded.c:
    python3 tests/irq_slice.py /path/to/out/hal_interrupt_bounded.c

Compiles the actual patched queue-drain function with a fake hardware queue.
The fake IRQ deasserts after the first read, as when an IRQ acknowledgement
clears coalesced notifications. Software continuation must drain the rest.
"""

import os
from pathlib import Path
import subprocess
import sys
import tempfile


def extract_function(source, name):
    start = source.index("static unsigned int " + name + "(")
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


PRELUDE = r"""
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
enum nrf_wifi_status { NRF_WIFI_STATUS_SUCCESS, NRF_WIFI_STATUS_FAIL };
struct nrf_wifi_hal_dev_ctx {
    struct { struct { int event_busy_queue; } hpqm_info; } rpu_info;
};
static unsigned remaining, fetched, pending, notified, fail_dequeue, fail_fetch;
void nrf70_facade_notify_host_irq(void) { pending = 1; notified++; }
static void nrf_wifi_osal_log_err(const char *fmt, ...) { (void)fmt; }
static enum nrf_wifi_status hal_rpu_hpq_dequeue(
    struct nrf_wifi_hal_dev_ctx *ctx, int *q, unsigned *address)
{
    (void)ctx; (void)q;
    if (fail_dequeue) return NRF_WIFI_STATUS_FAIL;
    *address = remaining ? remaining-- : 0;
    return NRF_WIFI_STATUS_SUCCESS;
}
static enum nrf_wifi_status hal_rpu_event_get(
    struct nrf_wifi_hal_dev_ctx *ctx, unsigned address)
{
    (void)ctx; (void)address;
    if (fail_fetch) return NRF_WIFI_STATUS_FAIL;
    fetched++;
    return NRF_WIFI_STATUS_SUCCESS;
}
"""

TEST = r"""
int main(void) {
    struct nrf_wifi_hal_dev_ctx ctx = {0};
    remaining = 3;
    pending = 1; /* Initial physical interrupt. No further hardware IRQs. */
    unsigned calls = 0;
    while (pending) {
        pending = 0;
        unsigned count = hal_rpu_event_get_all(&ctx);
        assert(count <= 1); /* Preserve the bounded runner contract. */
        assert(++calls <= 4);
        /* Hardware acknowledgement clears HOST_IRQ here. Only the software
         * pending flag can cause another invocation. */
    }
    assert(fetched == 3 && remaining == 0 && calls == 4 && notified == 3);
    assert(hal_rpu_event_get_all(&ctx) == 0 && !pending);
    fail_dequeue = 1;
    assert(hal_rpu_event_get_all(&ctx) == 0 && !pending);
    fail_dequeue = 0;
    fail_fetch = 1;
    remaining = 1;
    assert(hal_rpu_event_get_all(&ctx) == 0 && !pending);
    puts("IRQ slice: coalesced events drain, bounded work, empty/error paths pass");
}
"""


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: irq_slice.py <generated hal_interrupt_bounded.c>")
    source = Path(sys.argv[1]).read_text()
    function = extract_function(source, "hal_rpu_event_get_all")
    with tempfile.TemporaryDirectory() as directory:
        test = Path(directory) / "irq_slice.c"
        binary = Path(directory) / "irq_slice"
        test.write_text(PRELUDE + function + TEST)
        subprocess.run(
            [os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
             str(test), "-o", str(binary)], check=True
        )
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
