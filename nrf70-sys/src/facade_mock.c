/* SPDX-License-Identifier: BSD-3-Clause */
/* Host mock of the facade ABI. Connect validation must stay equivalent to
 * facade.c; the handshake is scripted: open -> AUTH/ASSOC/LINK, WPA2 with the
 * passphrase "wrong-password" -> AUTH/ASSOC/HANDSHAKE_FAILED(reason 23) and no
 * link, any other valid WPA2 credential -> AUTH/ASSOC/LINK, then
 * PORT_AUTHORIZED on the next process() call. A link info request is answered
 * at once with -42 dBm and 54 Mbit/s. Transmitted frames loop back to RX. */
#include "nrf70_facade.h"
#include <string.h>

#define MOCK_EVENTS 16
#define MOCK_RX 4

struct mock_rx_slot {
    uint16_t len;
    uint8_t data[NRF70_FACADE_MAX_FRAME_LEN];
};

static struct nrf70_facade_platform_ops ops;
static struct nrf70_facade_event queue[MOCK_EVENTS];
static struct mock_rx_slot rx[MOCK_RX];
static struct nrf70_facade_stats stats;
static struct nrf70_facade_link_info link;
static uint8_t head, count, rx_head, rx_count;
static uint8_t initialized, irq, linked, authorized, conn_active, secured, pending_authorize;

static void push(const struct nrf70_facade_event *event) {
    if (count == MOCK_EVENTS) {
        stats.dropped_events++;
        return;
    }
    queue[(head + count) % MOCK_EVENTS] = *event;
    count++;
}

static void simple_event(uint8_t kind, int32_t status) {
    struct nrf70_facade_event e = { .generation = stats.generation, .status = status, .kind = kind };
    push(&e);
}

static void clear_state(void) {
    linked = authorized = conn_active = secured = pending_authorize = 0;
    head = count = rx_head = rx_count = 0;
}

static void drop_connection(uint16_t reason) {
    conn_active = 0;
    if (linked)
        stats.link_downs++;
    linked = authorized = secured = pending_authorize = 0;
    stats.disconnects++;
    struct nrf70_facade_event e = {
        .generation = stats.generation, .kind = NRF70_FACADE_EVENT_DISCONNECTED, .reason_code = reason
    };
    push(&e);
}

int32_t nrf70_facade_init(const struct nrf70_facade_platform_ops *p, const uint8_t mac[6],
                          const uint8_t country[2]) {
    (void)mac;
    (void)country;
    if (!p || p->abi_version != NRF70_FACADE_ABI_VERSION || initialized)
        return NRF70_FACADE_INVALID;
    ops = *p;
    initialized = 1;
    clear_state();
    stats.generation++;
    return NRF70_FACADE_OK;
}

int32_t nrf70_facade_deinit(void) {
    if (!initialized)
        return NRF70_FACADE_NOT_INITIALIZED;
    initialized = 0;
    clear_state();
    return NRF70_FACADE_OK;
}

int32_t nrf70_facade_reset(const uint8_t mac[6], const uint8_t country[2]) {
    (void)mac;
    (void)country;
    if (!initialized)
        return NRF70_FACADE_NOT_INITIALIZED;
    clear_state();
    stats.generation++;
    stats.resets++;
    stats.firmware_restarts++;
    simple_event(NRF70_FACADE_EVENT_FIRMWARE_RESTART, 0);
    return NRF70_FACADE_OK;
}

int32_t nrf70_facade_set_country(const uint8_t c[2]) {
    return initialized && c ? NRF70_FACADE_OK : NRF70_FACADE_INVALID;
}

int32_t nrf70_facade_scan_start(const struct nrf70_facade_scan_request *r) {
    static const uint8_t ssid[] = "phase3-open-5g";
    if (!initialized)
        return NRF70_FACADE_NOT_INITIALIZED;
    if (!r || r->channel_count > NRF70_FACADE_MAX_CHANNELS)
        return NRF70_FACADE_INVALID;
    stats.scans_started++;
    struct nrf70_facade_event e = { .generation = stats.generation, .kind = NRF70_FACADE_EVENT_SCAN_RESULT };
    e.scan.ssid_len = sizeof(ssid) - 1;
    memcpy(e.scan.ssid, ssid, sizeof(ssid) - 1);
    e.scan.band = 1;
    e.scan.channel = r->channel_count ? r->channels[0].channel : 36;
    e.scan.rssi_dbm = -42;
    e.scan.bssid[0] = 2;
    e.scan.bssid[5] = 2;
    e.scan.security = NRF70_FACADE_SECURITY_OPEN;
    push(&e);
    e.kind = NRF70_FACADE_EVENT_SCAN_COMPLETE;
    memset(&e.scan, 0, sizeof(e.scan));
    push(&e);
    stats.scans_completed++;
    return NRF70_FACADE_OK;
}

int32_t nrf70_facade_scan_cancel(void) {
    stats.scans_cancelled++;
    simple_event(NRF70_FACADE_EVENT_SCAN_COMPLETE, NRF70_FACADE_CANCELLED);
    return NRF70_FACADE_OK;
}

int32_t nrf70_facade_connect_start(const struct nrf70_facade_connect_request *q) {
    if (!initialized)
        return NRF70_FACADE_NOT_INITIALIZED;
    if (conn_active)
        return NRF70_FACADE_BUSY;
    if (!q || q->ssid_len < 1 || q->ssid_len > NRF70_FACADE_MAX_SSID_LEN)
        return NRF70_FACADE_INVALID;
    if (!(q->frequency_mhz >= 2412 && q->frequency_mhz <= 2484) &&
        !(q->frequency_mhz >= 4900 && q->frequency_mhz <= 5900))
        return NRF70_FACADE_INVALID;
    if (q->mfp > 2)
        return NRF70_FACADE_INVALID;
    if (q->security == NRF70_FACADE_SECURITY_OPEN) {
        if (q->credential_kind != NRF70_FACADE_CREDENTIAL_NONE)
            return NRF70_FACADE_INVALID;
    } else if (q->security == NRF70_FACADE_SECURITY_WPA2_PSK ||
               q->security == NRF70_FACADE_SECURITY_WPA2_PSK_SHA256) {
        if (q->credential_kind == NRF70_FACADE_CREDENTIAL_PASSPHRASE) {
            if (q->credential_len < 8 || q->credential_len > 63)
                return NRF70_FACADE_INVALID;
        } else if (q->credential_kind == NRF70_FACADE_CREDENTIAL_PSK) {
            if (q->credential_len != 32)
                return NRF70_FACADE_INVALID;
        } else {
            return NRF70_FACADE_INVALID;
        }
    } else {
        return NRF70_FACADE_INVALID;
    }

    conn_active = 1;
    secured = q->security != NRF70_FACADE_SECURITY_OPEN;
    authorized = pending_authorize = 0;
    struct nrf70_facade_event e = {
        .generation = stats.generation, .kind = NRF70_FACADE_EVENT_AUTH, .frequency_mhz = q->frequency_mhz
    };
    push(&e);
    e.kind = NRF70_FACADE_EVENT_ASSOC;
    push(&e);
    if (secured && q->credential_kind == NRF70_FACADE_CREDENTIAL_PASSPHRASE && q->credential_len == 14 &&
        memcmp(q->credential, "wrong-password", 14) == 0) {
        stats.handshake_failures++;
        e.kind = NRF70_FACADE_EVENT_HANDSHAKE_FAILED;
        e.status = NRF70_FACADE_IO;
        e.reason_code = 23;
        push(&e);
        return NRF70_FACADE_OK;
    }
    e.kind = NRF70_FACADE_EVENT_LINK;
    e.link_up = 1;
    push(&e);
    linked = 1;
    stats.link_ups++;
    memset(&link, 0, sizeof(link));
    link.ssid_len = q->ssid_len;
    memcpy(link.ssid, q->ssid, q->ssid_len);
    memcpy(link.bssid, q->bssid, 6);
    link.security = q->security;
    link.rssi_dbm = INT8_MIN;
    link.frequency_mhz = q->frequency_mhz;
    /* Deferred so tests can observe the linked-but-unauthorized window. */
    pending_authorize = secured;
    return NRF70_FACADE_OK;
}

int32_t nrf70_facade_connect_abort(uint16_t reason) {
    if (!initialized)
        return NRF70_FACADE_NOT_INITIALIZED;
    if (!conn_active)
        return NRF70_FACADE_NOT_CONNECTED;
    drop_connection(reason);
    return NRF70_FACADE_OK;
}

int32_t nrf70_facade_disconnect(uint16_t reason) {
    if (!initialized)
        return NRF70_FACADE_NOT_INITIALIZED;
    drop_connection(reason);
    struct nrf70_facade_event e = {
        .generation = stats.generation, .kind = NRF70_FACADE_EVENT_LINK, .reason_code = reason
    };
    push(&e);
    return NRF70_FACADE_OK;
}

int32_t nrf70_facade_key_install(const struct nrf70_facade_key *k) {
    return initialized && k && k->key_len <= NRF70_FACADE_MAX_KEY_LEN && k->seq_len <= NRF70_FACADE_MAX_SEQ_LEN
               ? NRF70_FACADE_OK
               : NRF70_FACADE_INVALID;
}

int32_t nrf70_facade_key_remove(const struct nrf70_facade_key *k) {
    return initialized && k ? NRF70_FACADE_OK : NRF70_FACADE_INVALID;
}

int32_t nrf70_facade_controlled_port(uint8_t authorize, const uint8_t peer[6]) {
    if (!initialized || !peer)
        return NRF70_FACADE_INVALID;
    authorized = authorize != 0;
    return NRF70_FACADE_OK;
}

int32_t nrf70_facade_set_power_save(uint8_t enabled) {
    (void)enabled;
    return initialized ? NRF70_FACADE_OK : NRF70_FACADE_NOT_INITIALIZED;
}

int32_t nrf70_facade_link_info_request(void) {
    if (!initialized)
        return NRF70_FACADE_NOT_INITIALIZED;
    if (!linked)
        return NRF70_FACADE_NOT_CONNECTED;
    link.rssi_dbm = -42;
    link.tx_rate_kbps = 54000;
    simple_event(NRF70_FACADE_EVENT_LINK_INFO, 0);
    return NRF70_FACADE_OK;
}

void nrf70_facade_link_info_get(struct nrf70_facade_link_info *info) {
    if (info)
        *info = link;
}

int32_t nrf70_facade_coex_configure(uint8_t sr) {
    if (!initialized)
        return NRF70_FACADE_NOT_INITIALIZED;
    return sr > NRF70_FACADE_COEX_SR_IEEE802154 ? NRF70_FACADE_INVALID : NRF70_FACADE_OK;
}

int32_t nrf70_facade_coex_reset(void) {
    return initialized ? NRF70_FACADE_OK : NRF70_FACADE_NOT_INITIALIZED;
}

int32_t nrf70_facade_tx(uint32_t token, const uint8_t *frame, uint16_t len) {
    if (!initialized)
        return NRF70_FACADE_NOT_INITIALIZED;
    if (!linked || (secured && !authorized))
        return NRF70_FACADE_NOT_CONNECTED;
    if (!frame || len < 14 || len > NRF70_FACADE_MAX_FRAME_LEN)
        return NRF70_FACADE_INVALID;
    if (rx_count == MOCK_RX) {
        stats.tx_queue_full++;
        return NRF70_FACADE_QUEUE_FULL;
    }
    stats.tx_submitted++;
    stats.tx_copies++;
    struct mock_rx_slot *s = &rx[(rx_head + rx_count) % MOCK_RX];
    s->len = len;
    memcpy(s->data, frame, len);
    rx_count++;
    stats.rx_received++;
    stats.rx_copies++;
    if (rx_count > stats.rx_queue_high_water)
        stats.rx_queue_high_water = rx_count;
    struct nrf70_facade_event e = {
        .generation = stats.generation, .kind = NRF70_FACADE_EVENT_TX_COMPLETE, .token = token
    };
    push(&e);
    stats.tx_completed++;
    simple_event(NRF70_FACADE_EVENT_RX_READY, 0);
    return NRF70_FACADE_OK;
}

int32_t nrf70_facade_rx_pop(uint8_t *frame, uint16_t cap, struct nrf70_facade_rx_meta *meta) {
    if (!frame || !meta)
        return NRF70_FACADE_INVALID;
    if (!rx_count)
        return 0;
    struct mock_rx_slot *s = &rx[rx_head];
    if (cap < s->len)
        return NRF70_FACADE_INVALID;
    memcpy(frame, s->data, s->len);
    memset(meta, 0, sizeof(*meta));
    meta->generation = stats.generation;
    meta->length = s->len;
    rx_head = (rx_head + 1) % MOCK_RX;
    rx_count--;
    stats.rx_delivered++;
    return 1;
}

void nrf70_facade_notify_host_irq(void) {
    irq = 1;
}

uint32_t nrf70_facade_process(uint32_t budget) {
    uint32_t work = irq;
    irq = 0;
    if (budget && pending_authorize) {
        pending_authorize = 0;
        authorized = 1;
        stats.handshakes_completed++;
        simple_event(NRF70_FACADE_EVENT_PORT_AUTHORIZED, 0);
        work++;
    }
    return work;
}

uint32_t nrf70_facade_next_deadline_us(void) {
    return count || (initialized && (irq || pending_authorize)) ? 0 : NRF70_FACADE_NO_DEADLINE;
}

int32_t nrf70_facade_event_pop(struct nrf70_facade_event *e) {
    if (!e)
        return NRF70_FACADE_INVALID;
    if (!count)
        return 0;
    *e = queue[head];
    head = (head + 1) % MOCK_EVENTS;
    count--;
    return 1;
}

void nrf70_facade_stats_get(struct nrf70_facade_stats *s) {
    if (s)
        *s = stats;
}

uint8_t nrf70_facade_host_irq_active(void) {
    return ops.host_irq_active ? ops.host_irq_active(ops.context) : 0;
}

uint32_t nrf70_facade_now_us(void) {
    return ops.now_us ? ops.now_us(ops.context) : 0;
}

uint32_t nrf70_facade_sizeof_scan_request(void) { return sizeof(struct nrf70_facade_scan_request); }
uint32_t nrf70_facade_alignof_scan_request(void) { return _Alignof(struct nrf70_facade_scan_request); }
uint32_t nrf70_facade_sizeof_scan_result(void) { return sizeof(struct nrf70_facade_scan_result); }
uint32_t nrf70_facade_sizeof_connect_request(void) { return sizeof(struct nrf70_facade_connect_request); }
uint32_t nrf70_facade_sizeof_key(void) { return sizeof(struct nrf70_facade_key); }
uint32_t nrf70_facade_sizeof_event(void) { return sizeof(struct nrf70_facade_event); }
uint32_t nrf70_facade_sizeof_link_info(void) { return sizeof(struct nrf70_facade_link_info); }
uint32_t nrf70_facade_sizeof_rx_meta(void) { return sizeof(struct nrf70_facade_rx_meta); }
uint32_t nrf70_facade_sizeof_stats(void) { return sizeof(struct nrf70_facade_stats); }

_Static_assert(sizeof(enum nrf70_facade_status) == 4, "enum ABI");
