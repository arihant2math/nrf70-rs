"""Compile and test the production next-deadline logic without the firmware.

Run: python3 nrf70-rs/nrf70-sys/tests/deadline.py

The driver task sleeps for as long as nrf70_facade_next_deadline_us allows, so
a source it overlooks stalls the driver and one it reports forever spins it.
"""

import os
from pathlib import Path
import subprocess
import tempfile

src = Path(__file__).resolve().parent.parent / "src"


def extract(source, start_marker, end_marker):
    start = source.index(start_marker)
    return source[start:source.index(end_marker, start)]


facade = (src / "facade.c").read_text()
supplicant = (src / "supplicant.c").read_text()
code = (
    extract(supplicant, "uint32_t nrf70_supp_eloop_next_us(", "\n/* Sliced PBKDF2")
    + extract(facade, "static uint8_t conn_ready(void) {", "/* Runs at most one bounded action")
    + extract(facade, "uint32_t nrf70_facade_next_deadline_us(void) {",
              "int32_t nrf70_facade_event_pop(")
)

PRELUDE = r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define NRF70_FACADE_NO_DEADLINE 0xFFFFFFFFu
#define TASKLET_SLOTS 16u
#define TIMER_SLOTS 16u
#define SUPP_ELOOP_SLOTS 4u
enum conn_state {
    CONN_IDLE, CONN_DERIVE, CONN_SCAN_START, CONN_SCAN_WAIT, CONN_AUTH_START,
    CONN_AUTH_WAIT, CONN_SUPP_SETUP, CONN_ASSOC_WAIT, CONN_HANDSHAKE, CONN_AUTHORIZED
};
struct tasklet_slot { uint8_t used, pending; };
struct timer_slot { uint8_t used, armed; uint32_t deadline; };
struct supp_timeout { uint8_t used; uint32_t deadline_us; };
struct conn_ctx {
    uint8_t state, scan_fetch, scan_done, auth_ok, auth_fail, assoc_ok, assoc_fail, teardown;
};
static struct tasklet_slot tasklets[TASKLET_SLOTS];
static struct timer_slot timers[TIMER_SLOTS];
static struct supp_timeout supp_timeouts[SUPP_ELOOP_SLOTS];
static struct conn_ctx conn;
static uint8_t event_count, initialized, faulted, irq_pending, scan_fetch_pending, eapol_count;
static uint8_t supp_active;
static int (*irq_callback)(void *);
static uint32_t clock_us;
static uint32_t now_us(void) { return clock_us; }
static uint8_t nrf70_supp_active(void) { return supp_active; }
"""

TEST = r"""
static int on_irq(void *p) { (void)p; return 0; }
static void reset(void) {
    memset(tasklets, 0, sizeof(tasklets));
    memset(timers, 0, sizeof(timers));
    memset(supp_timeouts, 0, sizeof(supp_timeouts));
    memset(&conn, 0, sizeof(conn));
    event_count = faulted = irq_pending = scan_fetch_pending = eapol_count = supp_active = 0;
    initialized = 1;
    irq_callback = on_irq;
    clock_us = 1000;
}
#define NEXT nrf70_facade_next_deadline_us()
int main(void) {
    reset();
    assert(NEXT == NRF70_FACADE_NO_DEADLINE);

    /* Queued events are drained even when the facade can run nothing. */
    event_count = 1; assert(NEXT == 0);
    initialized = 0; assert(NEXT == 0);
    event_count = 0; assert(NEXT == NRF70_FACADE_NO_DEADLINE);

    /* process() returns at once while faulted, so pending work must not be
     * reported: it would never be consumed. */
    reset(); irq_pending = 1; tasklets[0].used = tasklets[0].pending = 1;
    assert(NEXT == 0);
    faulted = 1; assert(NEXT == NRF70_FACADE_NO_DEADLINE);

    /* Deferred work. An IRQ with no registered handler is not serviceable. */
    reset(); irq_pending = 1; assert(NEXT == 0);
    irq_callback = 0; assert(NEXT == NRF70_FACADE_NO_DEADLINE);
    reset(); scan_fetch_pending = 1; assert(NEXT == 0);
    reset(); tasklets[15].used = tasklets[15].pending = 1; assert(NEXT == 0);
    tasklets[15].used = 0; assert(NEXT == NRF70_FACADE_NO_DEADLINE);

    /* Connect states that act immediately... */
    static const uint8_t active[] = {CONN_DERIVE, CONN_SCAN_START, CONN_AUTH_START,
                                     CONN_SUPP_SETUP};
    for (unsigned i = 0; i < sizeof(active); i++) {
        reset(); conn.state = active[i]; assert(NEXT == 0);
    }
    /* ...and those that wait for an FMAC callback to set a flag. */
    static const uint8_t waiting[] = {CONN_IDLE, CONN_SCAN_WAIT, CONN_AUTH_WAIT,
                                      CONN_ASSOC_WAIT, CONN_HANDSHAKE, CONN_AUTHORIZED};
    for (unsigned i = 0; i < sizeof(waiting); i++) {
        reset(); conn.state = waiting[i]; assert(NEXT == NRF70_FACADE_NO_DEADLINE);
        conn.teardown = 1; assert(NEXT == 0);
    }
    reset(); conn.state = CONN_SCAN_WAIT; conn.scan_fetch = 1; assert(NEXT == 0);
    reset(); conn.state = CONN_SCAN_WAIT; conn.scan_done = 1; assert(NEXT == 0);
    reset(); conn.state = CONN_AUTH_WAIT; conn.auth_ok = 1; assert(NEXT == 0);
    reset(); conn.state = CONN_AUTH_WAIT; conn.auth_fail = 1; assert(NEXT == 0);
    reset(); conn.state = CONN_ASSOC_WAIT; conn.assoc_ok = 1; assert(NEXT == 0);
    reset(); conn.state = CONN_ASSOC_WAIT; conn.assoc_fail = 1; assert(NEXT == 0);
    reset(); conn.state = CONN_HANDSHAKE; eapol_count = 1; assert(NEXT == 0);
    reset(); conn.state = CONN_AUTHORIZED; eapol_count = 1; assert(NEXT == 0);

    /* Timers: the earliest armed one wins; expired means now. */
    reset();
    timers[3].used = timers[3].armed = 1; timers[3].deadline = 6000;
    timers[7].used = timers[7].armed = 1; timers[7].deadline = 3500;
    assert(NEXT == 2500);
    timers[7].armed = 0; assert(NEXT == 5000);
    clock_us = 6000; assert(NEXT == 0);
    clock_us = 9000; assert(NEXT == 0);
    timers[3].armed = 0; assert(NEXT == NRF70_FACADE_NO_DEADLINE);

    /* The 32-bit clock wraps every 71 minutes. */
    reset(); clock_us = 0xFFFFFF00u;
    timers[0].used = timers[0].armed = 1; timers[0].deadline = 0x00000100u;
    assert(NEXT == 0x200);
    clock_us = 0x00000101u; assert(NEXT == 0);

    /* Supplicant timeouts count only while a session exists. */
    reset(); supp_timeouts[2].used = 1; supp_timeouts[2].deadline_us = 1400;
    assert(NEXT == NRF70_FACADE_NO_DEADLINE);
    supp_active = 1; assert(NEXT == 400);
    timers[0].used = timers[0].armed = 1; timers[0].deadline = 1100; assert(NEXT == 100);
    timers[0].deadline = 9000; assert(NEXT == 400);
    clock_us = 1400; assert(NEXT == 0);

    puts("deadline: pending work, connect states, timers, wraparound and eloop pass");
}
"""

with tempfile.TemporaryDirectory() as directory:
    c = Path(directory) / "deadline.c"
    binary = Path(directory) / "deadline"
    c.write_text(PRELUDE + code + TEST)
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
