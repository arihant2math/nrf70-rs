/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef NRF70_FACADE_H
#define NRF70_FACADE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NRF70_FACADE_ABI_VERSION 3u
#define NRF70_FACADE_MAX_CHANNELS 32u
#define NRF70_FACADE_MAX_SSID_LEN 32u
#define NRF70_FACADE_MAX_FRAME_LEN 1514u
#define NRF70_FACADE_MAX_KEY_LEN 64u
#define NRF70_FACADE_MAX_SEQ_LEN 16u
#define NRF70_FACADE_MAX_CREDENTIAL_LEN 64u

/* Fixed values: these are part of the Rust/C ABI. */
enum nrf70_facade_status {
    NRF70_FACADE_OK = 0,
    NRF70_FACADE_INVALID = -1,
    NRF70_FACADE_BUSY = -2,
    NRF70_FACADE_IO = -3,
    NRF70_FACADE_NO_MEMORY = -4,
    NRF70_FACADE_NOT_INITIALIZED = -5,
    NRF70_FACADE_CANCELLED = -6,
    NRF70_FACADE_FATAL = -7,
    NRF70_FACADE_QUEUE_FULL = -8,
    NRF70_FACADE_NOT_CONNECTED = -9
};

enum nrf70_facade_event_kind {
    NRF70_FACADE_EVENT_SCAN_RESULT = 1,
    NRF70_FACADE_EVENT_SCAN_COMPLETE = 2,
    NRF70_FACADE_EVENT_FATAL = 3,
    NRF70_FACADE_EVENT_AUTH = 4,
    NRF70_FACADE_EVENT_ASSOC = 5,
    NRF70_FACADE_EVENT_DISCONNECTED = 6,
    NRF70_FACADE_EVENT_LINK = 7,
    NRF70_FACADE_EVENT_TX_COMPLETE = 8,
    NRF70_FACADE_EVENT_RX_READY = 9,
    NRF70_FACADE_EVENT_FIRMWARE_RESTART = 10,
    /* The 4-way handshake finished and the controlled port is authorized. */
    NRF70_FACADE_EVENT_PORT_AUTHORIZED = 11,
    /* The supplicant gave up: status is a facade status, reason_code an 802.11 reason. */
    NRF70_FACADE_EVENT_HANDSHAKE_FAILED = 12
};

enum nrf70_facade_security {
    NRF70_FACADE_SECURITY_OPEN = 0,
    NRF70_FACADE_SECURITY_WPA2_PSK = 1,
    NRF70_FACADE_SECURITY_WPA2_PSK_SHA256 = 2,
    NRF70_FACADE_SECURITY_WPA3_SAE = 3,
    NRF70_FACADE_SECURITY_OTHER = 255
};

enum nrf70_facade_key_type {
    NRF70_FACADE_KEY_GROUP = 0,
    NRF70_FACADE_KEY_PAIRWISE = 1,
    NRF70_FACADE_KEY_PEER = 2
};

struct nrf70_facade_channel {
    uint8_t band;    /* 1 is 5 GHz; other values are rejected by the safe crate. */
    uint8_t channel;
};

struct nrf70_facade_scan_request {
    uint8_t passive;
    uint8_t channel_count;
    uint8_t ssid_len;
    uint8_t reserved;
    uint16_t dwell_active_ms;
    uint16_t dwell_passive_ms;
    uint16_t max_results;
    uint8_t ssid[NRF70_FACADE_MAX_SSID_LEN];
    struct nrf70_facade_channel channels[NRF70_FACADE_MAX_CHANNELS];
};

struct nrf70_facade_scan_result {
    uint8_t ssid_len;
    uint8_t ssid[NRF70_FACADE_MAX_SSID_LEN];
    uint8_t channel;
    uint8_t band;
    int8_t rssi_dbm;
    uint8_t bssid[6];
    uint8_t security;
    uint8_t mfp;
};

enum nrf70_facade_credential_kind {
    NRF70_FACADE_CREDENTIAL_NONE = 0,       /* open network */
    NRF70_FACADE_CREDENTIAL_PASSPHRASE = 1, /* 8..63 byte WPA2 passphrase */
    NRF70_FACADE_CREDENTIAL_PSK = 2         /* raw 32-byte PMK */
};

enum nrf70_facade_mfp {
    NRF70_FACADE_MFP_DISABLED = 0,
    NRF70_FACADE_MFP_OPTIONAL = 1,
    NRF70_FACADE_MFP_REQUIRED_ = 2
};

/* One connect target. The caller zeroizes its copy after the call returns;
 * the facade zeroizes every internal credential copy when the PMK has been
 * derived and on session teardown. The PMK itself lives in the supplicant
 * for rekeying and is cleared on disconnect, abort, reset, and deinit. */
struct nrf70_facade_connect_request {
    uint8_t ssid_len;
    uint8_t ssid[NRF70_FACADE_MAX_SSID_LEN];
    uint8_t bssid[6];
    uint16_t frequency_mhz;
    uint8_t security;        /* enum nrf70_facade_security: OPEN or WPA2_PSK */
    uint8_t mfp;             /* enum nrf70_facade_mfp */
    uint8_t credential_kind; /* enum nrf70_facade_credential_kind */
    uint8_t credential_len;
    uint8_t credential[NRF70_FACADE_MAX_CREDENTIAL_LEN];
};

/* Kept narrow so Phase 3 can drive key installation without exposing FMAC structs. */
struct nrf70_facade_key {
    uint8_t key_type;
    uint8_t key_index;
    uint8_t key_len;
    uint8_t seq_len;
    uint32_t cipher_suite;
    uint8_t peer[6];
    uint8_t key[NRF70_FACADE_MAX_KEY_LEN];
    uint8_t sequence[NRF70_FACADE_MAX_SEQ_LEN];
};

struct nrf70_facade_event {
    uint32_t generation;
    int32_t status;
    uint32_t token;
    uint16_t frequency_mhz;
    int8_t rssi_dbm;
    uint8_t kind;
    uint16_t reason_code;
    uint8_t link_up;
    uint8_t reserved;
    struct nrf70_facade_scan_result scan;
};

struct nrf70_facade_rx_meta {
    uint32_t generation;
    uint16_t length;
    uint16_t reserved;
    int8_t rssi_dbm;
    uint8_t reserved2[3];
};

struct nrf70_facade_stats {
    uint32_t generation;
    uint32_t scans_started;
    uint32_t scans_completed;
    uint32_t scans_cancelled;
    uint32_t dropped_events;
    uint32_t allocation_failures;
    uint32_t spi_errors;
    uint32_t fatal_errors;
    uint32_t max_c_call_us;
    uint32_t max_spi_transfer_us;
    uint32_t max_osal_delay_us;
    uint32_t arena_used;
    uint32_t arena_high_water;
    uint32_t tx_submitted;
    uint32_t tx_completed;
    uint32_t tx_failed;
    uint32_t tx_queue_full;
    uint32_t rx_received;
    uint32_t rx_delivered;
    uint32_t rx_dropped;
    uint32_t rx_invalid;
    uint32_t link_ups;
    uint32_t link_downs;
    uint32_t disconnects;
    uint32_t firmware_restarts;
    uint32_t resets;
    uint32_t tx_copies;
    uint32_t rx_copies;
    uint32_t rx_queue_high_water;
    uint32_t nbuf_in_use;
    uint32_t nbuf_high_water;
    uint32_t eapol_rx;
    uint32_t eapol_rx_dropped;
    uint32_t eapol_tx;
    uint32_t eapol_tx_failed;
    uint32_t handshakes_completed;
    uint32_t handshake_failures;
    uint32_t rekeys;
    uint32_t rx_dropped_unauthorized;
};

/* All callbacks are synchronous and are called only by the serialized driver task,
 * except host_irq_active, which must only sample the GPIO. */
struct nrf70_facade_platform_ops {
    uint32_t abi_version;
    void *context;
    void *(*alloc)(void *context, uint32_t size, uint32_t align, uint8_t zeroed);
    void (*free)(void *context, void *ptr);
    int32_t (*power_on)(void *context);
    void (*power_off)(void *context);
    int32_t (*bus_init)(void *context);
    void (*bus_deinit)(void *context);
    int32_t (*read_reg32)(void *context, uint32_t address, uint32_t *value);
    int32_t (*write_reg32)(void *context, uint32_t address, uint32_t value);
    int32_t (*read)(void *context, uint32_t address, uint8_t *dst, uint32_t length);
    int32_t (*write)(void *context, uint32_t address, const uint8_t *src, uint32_t length);
    int32_t (*sleep)(void *context);
    int32_t (*wake)(void *context);
    int32_t (*power_status)(void *context);
    void (*delay_us)(void *context, uint32_t delay_us);
    uint32_t (*now_us)(void *context);
    uint8_t (*random_u8)(void *context);
    uint8_t (*host_irq_active)(void *context);
    void (*log)(void *context, uint8_t level, const char *message);
    void (*fatal)(void *context, int32_t reason, const char *message);
};

int32_t nrf70_facade_init(const struct nrf70_facade_platform_ops *ops,
                          const uint8_t mac[6], const uint8_t country[2]);
int32_t nrf70_facade_deinit(void);
int32_t nrf70_facade_reset(const uint8_t mac[6], const uint8_t country[2]);
int32_t nrf70_facade_set_country(const uint8_t country[2]);
int32_t nrf70_facade_scan_start(const struct nrf70_facade_scan_request *request);
int32_t nrf70_facade_scan_cancel(void);
/* Starts the connect state machine: PMK derivation (sliced across process
 * calls), a connect-reason scan that captures the AP RSN IE, authenticate,
 * associate with the supplicant's RSN IE and a host-controlled port, then the
 * 4-way handshake driven by EAPOL frames. Completion is signalled by
 * PORT_AUTHORIZED (secured) or LINK up (open); failure by HANDSHAKE_FAILED,
 * AUTH/ASSOC with nonzero status, or DISCONNECTED. */
int32_t nrf70_facade_connect_start(const struct nrf70_facade_connect_request *request);
/* Cancels a pending or completed connect: tears down supplicant state,
 * zeroizes secrets, and deauthenticates if the radio is associated. */
int32_t nrf70_facade_connect_abort(uint16_t reason_code);
int32_t nrf70_facade_disconnect(uint16_t reason_code);
int32_t nrf70_facade_key_install(const struct nrf70_facade_key *key);
int32_t nrf70_facade_key_remove(const struct nrf70_facade_key *key);
int32_t nrf70_facade_controlled_port(uint8_t authorized, const uint8_t peer[6]);
int32_t nrf70_facade_set_power_save(uint8_t enabled);
/* Copies the frame into a C-owned nbuf. token is returned by TX_COMPLETE. */
int32_t nrf70_facade_tx(uint32_t token, const uint8_t *frame, uint16_t length);
/* Atomically copies and releases one queued C RX buffer. 0 means no frame, 1 means copied. */
int32_t nrf70_facade_rx_pop(uint8_t *frame, uint16_t capacity,
                            struct nrf70_facade_rx_meta *meta);
/* HOST_IRQ ISR calls no C. Rust calls this later from thread mode. */
void nrf70_facade_notify_host_irq(void);
/* Runs at most budget deferred callbacks. Returns the number run. */
uint32_t nrf70_facade_process(uint32_t budget);
int32_t nrf70_facade_event_pop(struct nrf70_facade_event *event);
void nrf70_facade_stats_get(struct nrf70_facade_stats *stats);
uint8_t nrf70_facade_host_irq_active(void);
uint32_t nrf70_facade_now_us(void);

/* Build-time ABI probes used by Rust assertions. */
uint32_t nrf70_facade_sizeof_scan_request(void);
uint32_t nrf70_facade_alignof_scan_request(void);
uint32_t nrf70_facade_sizeof_scan_result(void);
uint32_t nrf70_facade_sizeof_connect_request(void);
uint32_t nrf70_facade_sizeof_key(void);
uint32_t nrf70_facade_sizeof_event(void);
uint32_t nrf70_facade_sizeof_rx_meta(void);
uint32_t nrf70_facade_sizeof_stats(void);

#ifdef __cplusplus
}
#endif
#endif
