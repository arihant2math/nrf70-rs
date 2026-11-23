"""Exercise generated RX validation with production facade nbuf operations.

Run after building: python3 nrf70-sys/tests/rx.py /path/to/out/rx_checked.c
Uses host ASan/UBSan, fake HAL packet copies/refills and a consuming RX callback.
Only the configured STA data path is enabled; no hardware is accessed.
"""

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "vendor/nrf70-bm/nrf_wifi/fw_if/umac_if"


def function(source, name):
    match = re.search(
        r"(?:static\s+)?(?:(?:enum|struct)\s+\w+|unsigned\s+(?:int|short)|void|int)"
        r"\s*\*?\s*\b" + name + r"\([^;{}]*\)\s*\{", source
    )
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


PRELUDE = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define NRF70_STA_MODE
#define __NRF_WIFI_PKD __attribute__((packed))
#define RX_BUF_HEADROOM 4
#define MAX_NUM_OF_RX_QUEUES 3
#define MAX_NUM_VIFS 1
#define PKT_TYPE_MPDU 0
#define PKT_TYPE_MSDU_WITH_MAC 1
#define PKT_TYPE_MSDU 2
#define NRF70_FACADE_OK 0
#define NRF70_FACADE_NO_MEMORY (-4)
#define mem_free free
#define nrf_wifi_osal_mem_cpy memcpy
#define nrf_wifi_osal_mem_set memset
#define nrf_wifi_osal_nbuf_data_get nbuf_data
#define nrf_wifi_osal_nbuf_data_size nbuf_size
#define nrf_wifi_osal_nbuf_free nbuf_free
static struct { unsigned nbuf_in_use, nbuf_high_water; } counters;
static void *try_alloc(size_t n, uint8_t zeroed) { return zeroed ? calloc(1, n) : malloc(n); }
static void fatal(int32_t reason, const char *msg) { (void)reason; (void)msg; abort(); }
static struct nbuf *tx_in_call;
static uint8_t tx_freed_in_call;
static void tx_complete(uint32_t token, int32_t status) {
    (void)token; (void)status; assert(!"RX buffer reported as TX");
}
enum nrf_wifi_status { NRF_WIFI_STATUS_SUCCESS, NRF_WIFI_STATUS_FAIL };
enum { NRF_WIFI_RX_PKT_DATA, NRF_WIFI_RX_PKT_BCN_PRB_RSP, NRF_WIFI_RAW_RX_PKT };
enum nrf_wifi_fmac_rx_cmd_type { NRF_WIFI_FMAC_RX_CMD_TYPE_INIT };
struct nrf_wifi_fmac_rx_pool_map_info { unsigned pool_id, buf_id; };
struct nrf_wifi_fmac_buf_map_info { unsigned long nwb; bool mapped; };
struct nrf_wifi_fmac_vif_ctx { void *os_vif_ctx; };
struct nrf_wifi_sys_fmac_dev_ctx {
    struct nrf_wifi_fmac_vif_ctx *vif_ctx[MAX_NUM_VIFS];
    struct nrf_wifi_fmac_buf_map_info rx_buf_info[6];
};
struct nrf_wifi_sys_fmac_priv {
    unsigned num_rx_bufs, rx_desc[MAX_NUM_OF_RX_QUEUES];
    struct { unsigned num_bufs, buf_sz; } rx_buf_pools[MAX_NUM_OF_RX_QUEUES];
    struct {
        void (*process_rssi_from_rx)(void *, short);
        void (*rx_frm_callbk_fn)(void *, void *);
    } callbk_fns;
};
struct nrf_wifi_fmac_dev_ctx {
    struct nrf_wifi_sys_fmac_priv *fpriv;
    struct nrf_wifi_sys_fmac_dev_ctx *priv;
    void *hal_dev_ctx;
};
struct rx_info { unsigned descriptor_id, rx_pkt_len, pkt_type; };
struct nrf_wifi_rx_buff {
    struct { unsigned len; } umac_head;
    unsigned wdev_id, rx_pkt_type, rx_pkt_cnt, mac_header_len;
    short signal;
    struct rx_info rx_buff_info[];
};
#define wifi_dev_priv(ctx) ((ctx)->priv)
#define wifi_fmac_priv(ctx) (ctx)
static void nrf_wifi_osal_log_err(const char *fmt, ...) { (void)fmt; }
"""

FAKES = r"""
enum fault {
    NORMAL, SHORT_FRAME, BAD_MAC_LEN, OVERSIZE, BAD_PKT_TYPE, BAD_FRAME_TYPE,
    FAIL_PUT, FAIL_HEAD_PULL, FAIL_CONVERT_PULL, FAIL_AMSDU_PULL, FAIL_PUSH,
    SHORT_ADDR4, SHORT_LLC, EMPTY_FRAME
};
static enum fault fault;
static unsigned put_calls, pulls, pushes, unmaps, copies, refills, delivered;
static unsigned last_unmap[6];
static uint8_t wire[6][256], expected[18];
static struct nrf_wifi_sys_fmac_priv priv;
static struct nrf_wifi_sys_fmac_dev_ctx dev;
static struct nrf_wifi_fmac_vif_ctx vif;
static struct nrf_wifi_fmac_dev_ctx ctx = { &priv, &dev, NULL };
static void *nrf_wifi_osal_nbuf_data_put(void *p, unsigned n) {
    if (++put_calls == 1 && fault == FAIL_PUT) return NULL;
    return nbuf_put(p, n);
}
static void *nrf_wifi_osal_nbuf_data_pull(void *p, unsigned n) {
    ++pulls;
    if ((pulls == 1 && fault == FAIL_HEAD_PULL) ||
        (pulls == 2 && fault == FAIL_CONVERT_PULL) ||
        (pulls == 3 && fault == FAIL_AMSDU_PULL)) return NULL;
    return nbuf_pull(p, n);
}
static void *nrf_wifi_osal_nbuf_data_push(void *p, unsigned n) {
    if (++pushes == 1 && fault == FAIL_PUSH) return NULL;
    return nbuf_push(p, n);
}
static unsigned long nrf_wifi_sys_hal_buf_unmap_rx(
    void *hal, unsigned len, unsigned pool, unsigned id)
{
    (void)hal;
    assert(pool < MAX_NUM_OF_RX_QUEUES && id < priv.rx_buf_pools[pool].num_bufs);
    unsigned desc = priv.rx_desc[pool] + id;
    struct nrf_wifi_fmac_buf_map_info *info = &dev.rx_buf_info[desc];
    assert(info->mapped && info->nwb);
    /* Reject before HAL: a too-large request would copy past the mapped slot. */
    assert(len <= priv.rx_buf_pools[pool].buf_sz);
    struct nbuf *n = (void *)info->nwb;
    assert(n->len == 0 && n->data == n->base);
    if (len) { memcpy(n->base + RX_BUF_HEADROOM, wire[desc], len); copies++; }
    unmaps++;
    last_unmap[desc] = len;
    return (unsigned long)n->base;
}
static enum nrf_wifi_status nrf_wifi_fmac_rx_cmd_send(
    struct nrf_wifi_fmac_dev_ctx *fmac, enum nrf_wifi_fmac_rx_cmd_type cmd,
    unsigned desc)
{
    assert(fmac == &ctx && cmd == NRF_WIFI_FMAC_RX_CMD_TYPE_INIT && desc < 6);
    struct nrf_wifi_fmac_buf_map_info *info = &dev.rx_buf_info[desc];
    assert(!info->mapped && !info->nwb);
    info->nwb = (unsigned long)nbuf_alloc(priv.rx_buf_pools[desc / 2].buf_sz +
                                        RX_BUF_HEADROOM);
    assert(info->nwb);
    info->mapped = true;
    refills++;
    return NRF_WIFI_STATUS_SUCCESS;
}
static void rssi(void *v, short signal) { (void)v; (void)signal; }
static void receive(void *v, void *p) {
    (void)v;
    /* Ownership must be detached before the callback can synchronously free. */
    for (unsigned i = 0; i < 6; i++) assert(dev.rx_buf_info[i].nwb != (unsigned long)p);
    assert(nbuf_size(p) == sizeof(expected));
    assert(memcmp(nbuf_data(p), expected, sizeof(expected)) == 0);
    delivered++;
    nbuf_free(p);
}
"""

TEST = r"""
static unsigned packet(unsigned desc, unsigned type, unsigned fc, unsigned mac_len) {
    uint8_t *p = wire[desc];
    memset(p, 0, 256);
    if (type == PKT_TYPE_MPDU) {
        struct nrf_wifi_fmac_ieee80211_hdr h = { .fc = fc };
        memset(h.addr_1, 0x11, 6); memset(h.addr_2, 0x22, 6);
        memset(h.addr_3, 0x33, 6); memset(h.addr_4, 0x44, 6);
        memcpy(p, &h, mac_len);
        unsigned src = fc == (NRF_WIFI_FCTL_TODS | NRF_WIFI_FCTL_FROMDS) ? 0x44 :
                       fc == NRF_WIFI_FCTL_FROMDS ? 0x33 : 0x22;
        memset(expected, fc == NRF_WIFI_FCTL_TODS ? 0x33 : 0x11, 6);
        memset(expected + 6, src, 6);
        p += mac_len;
    } else {
        if (type == PKT_TYPE_MSDU_WITH_MAC) p += mac_len;
        memset(p, 0x11, 6); memset(p + 6, 0x33, 6);
        p[12] = 0; p[13] = 12;
        memcpy(expected, p, 12);
        p += sizeof(struct nrf_wifi_fmac_amsdu_hdr);
    }
    const uint8_t body[] = {0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 1, 2, 3, 4};
    memcpy(p, body, sizeof(body));
    memcpy(expected + 12, body + 6, 6);
    return (unsigned)(p - wire[desc]) + sizeof(body);
}
static void run(unsigned type, unsigned fc, enum fault failure, bool multi) {
    fault = failure;
    put_calls = pulls = pushes = unmaps = copies = refills = delivered = 0;
    memset(last_unmap, 0xff, sizeof(last_unmap));
    unsigned mac_len = fc == (NRF_WIFI_FCTL_TODS | NRF_WIFI_FCTL_FROMDS) ? 30 : 24;
    unsigned count = multi ? 2 : 1;
    unsigned event_size = sizeof(struct nrf_wifi_rx_buff) + count * sizeof(struct rx_info);
    struct nrf_wifi_rx_buff *event = calloc(1, event_size);
    assert(event);
    event->umac_head.len = event_size;
    event->rx_pkt_type = NRF_WIFI_RX_PKT_DATA;
    event->rx_pkt_cnt = count;
    event->mac_header_len = mac_len;
    for (unsigned i = 0; i < event->rx_pkt_cnt; i++) {
        unsigned desc = i * 2; /* Different pools exercise pool-relative IDs. */
        assert(nrf_wifi_fmac_rx_cmd_send(&ctx, NRF_WIFI_FMAC_RX_CMD_TYPE_INIT, desc)
               == NRF_WIFI_STATUS_SUCCESS);
        event->rx_buff_info[i].descriptor_id = desc;
        event->rx_buff_info[i].pkt_type = type;
        event->rx_buff_info[i].rx_pkt_len = packet(desc, type, fc, mac_len);
    }
    refills = 0;
    switch (failure) {
    case EMPTY_FRAME: event->rx_buff_info[0].rx_pkt_len = 0; break;
    case SHORT_FRAME: event->rx_buff_info[0].rx_pkt_len = 1; break;
    case SHORT_LLC: event->rx_buff_info[0].rx_pkt_len -= 5; break;
    case BAD_MAC_LEN: event->mac_header_len = 250; break;
    case OVERSIZE: event->rx_buff_info[0].rx_pkt_len = priv.rx_buf_pools[0].buf_sz + 1; break;
    case BAD_PKT_TYPE: event->rx_buff_info[0].pkt_type = 255; break;
    case BAD_FRAME_TYPE: event->rx_pkt_type = 255; break;
    case SHORT_ADDR4: event->mac_header_len = 24; break;
    default: break;
    }
    enum nrf_wifi_status status = nrf_wifi_fmac_rx_event_process(&ctx, event);
    assert(status == (failure == NORMAL ? NRF_WIFI_STATUS_SUCCESS : NRF_WIFI_STATUS_FAIL));
    assert(delivered == (failure == NORMAL ? event->rx_pkt_cnt : multi ? 1u : 0u));
    assert(unmaps == event->rx_pkt_cnt && refills == event->rx_pkt_cnt);
    bool no_copy = failure == OVERSIZE || failure == EMPTY_FRAME;
    assert(copies == event->rx_pkt_cnt - no_copy);
    if (no_copy) assert(last_unmap[0] == 0);
    if (failure == FAIL_PUT) assert(put_calls >= 1);
    if (failure == FAIL_HEAD_PULL) assert(pulls >= 1);
    if (failure == FAIL_CONVERT_PULL) assert(pulls >= 2);
    if (failure == FAIL_AMSDU_PULL) assert(pulls >= 3);
    if (failure == FAIL_PUSH) assert(pushes >= 1);
    assert(counters.nbuf_in_use == event->rx_pkt_cnt);
    for (unsigned i = 0; i < event->rx_pkt_cnt; i++) {
        struct nrf_wifi_fmac_buf_map_info *info = &dev.rx_buf_info[i * 2];
        assert(info->mapped && info->nwb && nbuf_size((void *)info->nwb) == 0);
        nbuf_free((void *)info->nwb);
        *info = (struct nrf_wifi_fmac_buf_map_info){0};
    }
    free(event);
    assert(counters.nbuf_in_use == 0);
}
int main(void) {
    priv.num_rx_bufs = 6;
    priv.callbk_fns.process_rssi_from_rx = rssi;
    priv.callbk_fns.rx_frm_callbk_fn = receive;
    dev.vif_ctx[0] = &vif;
    for (unsigned i = 0; i < MAX_NUM_OF_RX_QUEUES; i++) {
        priv.rx_desc[i] = 2 * i;
        priv.rx_buf_pools[i].num_bufs = 2;
        priv.rx_buf_pools[i].buf_sz = 128 + 64 * i;
    }
    struct nrf_wifi_fmac_rx_pool_map_info pool;
    for (unsigned desc = 0; desc < 6; desc++) {
        assert(nrf_wifi_fmac_map_desc_to_pool(&ctx, desc, &pool) == NRF_WIFI_STATUS_SUCCESS);
        assert(pool.pool_id == desc / 2 && pool.buf_id == desc % 2);
    }
    assert(nrf_wifi_fmac_map_desc_to_pool(&ctx, 6, &pool) == NRF_WIFI_STATUS_FAIL);
    assert(nrf_wifi_fmac_map_desc_to_pool(&ctx, UINT_MAX, &pool) == NRF_WIFI_STATUS_FAIL);
    for (unsigned type = PKT_TYPE_MPDU; type <= PKT_TYPE_MSDU; type++) {
        run(type, NRF_WIFI_FCTL_FROMDS, NORMAL, false);
        run(type, NRF_WIFI_FCTL_FROMDS, EMPTY_FRAME, true);
        run(type, NRF_WIFI_FCTL_FROMDS, SHORT_FRAME, true);
        run(type, NRF_WIFI_FCTL_FROMDS, SHORT_LLC, true);
        run(type, NRF_WIFI_FCTL_FROMDS, OVERSIZE, true);
        run(type, NRF_WIFI_FCTL_FROMDS, BAD_PKT_TYPE, true);
        run(type, NRF_WIFI_FCTL_FROMDS, BAD_FRAME_TYPE, false);
        run(type, NRF_WIFI_FCTL_FROMDS, FAIL_PUT, true);
        run(type, NRF_WIFI_FCTL_FROMDS, FAIL_HEAD_PULL, true);
        run(type, NRF_WIFI_FCTL_FROMDS, FAIL_CONVERT_PULL, true);
        run(type, NRF_WIFI_FCTL_FROMDS, FAIL_PUSH, true);
        if (type != PKT_TYPE_MSDU) run(type, NRF_WIFI_FCTL_FROMDS, BAD_MAC_LEN, false);
    }
    run(PKT_TYPE_MSDU_WITH_MAC, NRF_WIFI_FCTL_FROMDS, FAIL_AMSDU_PULL, true);
    run(PKT_TYPE_MPDU, NRF_WIFI_FCTL_TODS | NRF_WIFI_FCTL_FROMDS, NORMAL, false);
    run(PKT_TYPE_MPDU, NRF_WIFI_FCTL_TODS | NRF_WIFI_FCTL_FROMDS, SHORT_ADDR4, false);
    run(PKT_TYPE_MPDU, NRF_WIFI_FCTL_TODS, NORMAL, false);
    run(PKT_TYPE_MPDU, 0, NORMAL, false);
    /* Direct helper calls use exact-sized buffers, exposing short header reads
       to ASan rather than hiding them in the spare capacity of an RX pool. */
    fault = NORMAL;
    for (unsigned len = 0; len < sizeof(struct nrf_wifi_fmac_amsdu_hdr) + 8; len++) {
        void *n = nbuf_alloc(len ? len : 1);
        assert(n && nbuf_put(n, len));
        memset(nbuf_data(n), 0, len);
        assert(nrf_wifi_convert_amsdu_to_eth(n) == NRF_WIFI_STATUS_FAIL);
        nbuf_free(n);
    }
    struct nrf_wifi_fmac_ieee80211_hdr hdr = {0};
    void *n = nbuf_alloc(4);
    assert(n && nbuf_put(n, 4));
    assert(nrf_wifi_convert_to_eth(n, &hdr, 0x0800) == NRF_WIFI_STATUS_FAIL);
    assert(nbuf_size(n) == 4); /* Natural push failure: no headroom. */
    nbuf_free(n);
    assert(counters.nbuf_in_use == 0);
    printf("RX: conversion, bounds, operation failures, ownership and refill pass\n");
}
"""


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: rx.py <generated rx_checked.c>")
    source = Path(sys.argv[1]).read_text()
    facade = (ROOT / "src/facade.c").read_text()
    util_header = (VENDOR / "inc/common/fmac_util.h").read_text()
    code = PRELUDE
    code += "\n".join(re.findall(r"^#define NRF_WIFI_\w+ [^\n/]+", util_header, re.M)) + "\n"
    for name in ("ieee80211", "eth", "amsdu"):
        code += re.search(r"struct nrf_wifi_fmac_" + name + r"_hdr \{.*?__NRF_WIFI_PKD;",
                          util_header, re.S).group(0) + "\n"
    code += re.search(r"^struct nbuf \{.*?\};", facade, re.M | re.S).group(0) + "\n"
    for name in ("nbuf_try_alloc", "nbuf_alloc", "nbuf_free", "nbuf_size", "nbuf_data", "nbuf_put",
                 "nbuf_pull", "nbuf_push"):
        code += function(facade, name)
    code += FAKES
    code += function((VENDOR / "src/common/fmac_util.c").read_text(),
                     "nrf_wifi_util_rx_get_eth_type")
    for name in ("nrf_wifi_fmac_map_desc_to_pool", "nrf_wifi_get_skip_header_bytes",
                 "nrf_wifi_convert_amsdu_to_eth", "nrf_wifi_convert_to_eth",
                 "nrf_wifi_fmac_rx_event_process"):
        code += function(source, name)
    with tempfile.TemporaryDirectory() as directory:
        test, binary = Path(directory) / "rx.c", Path(directory) / "rx"
        test.write_text(code + TEST)
        subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra",
                        "-Werror", "-Wno-unused-but-set-variable", "-g",
                        "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                        "-fno-omit-frame-pointer", str(test), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
