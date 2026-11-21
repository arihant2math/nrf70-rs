/* SPDX-License-Identifier: BSD-3-Clause */
/* WPA2-Personal supplicant: hostap wpa_sm session, os_ and libc shims, a
 * mini-eloop, and sliced PBKDF2. Compiled inside the hostap cc build with the
 * same defines. */
#include "includes.h"
#include "common.h"
#include "common/defs.h"
#include "common/eapol_common.h"
#include "common/wpa_common.h"
#include "crypto/sha1.h"
#include "rsn_supp/wpa.h"
#include "utils/eloop.h"
#include "supplicant.h"

int nrf70_supp_errno; /* referenced by the shim <errno.h>; nothing reads it */

/* libc interposers beyond the set facade.c provides. Referenced only by hostap
 * helper paths that are unreachable in the WPA2-PSK subset but must link. */
void *nrf70_os_memcpy(void *d, const void *s, size_t n);
void *nrf70_os_memset(void *d, int v, size_t n);
void nrf70_os_free(void *p);
void *nrf70_os_malloc(size_t n);
size_t nrf70_os_strlen(const char *s);

void *nrf70_os_memmove(void *d, const void *s, size_t n) {
    uint8_t *dd = d; const uint8_t *ss = s;
    if (dd == ss || !n) return d;
    if (dd < ss) { while (n--) *dd++ = *ss++; }
    else { dd += n; ss += n; while (n--) *--dd = *--ss; }
    return d;
}
/* Growing is unsupported (original block size unknown). Only unreachable
 * helper paths call realloc, and they treat NULL as out-of-memory. */
void *nrf70_os_realloc(void *p, size_t n) { (void)p; (void)n; return NULL; }
char *nrf70_os_strdup(const char *s) {
    size_t n = nrf70_os_strlen(s) + 1u;
    char *d = nrf70_os_malloc(n);
    if (d) nrf70_os_memcpy(d, s, n);
    return d;
}
int nrf70_os_strncmp(const char *a, const char *b, size_t n) {
    while (n && *a && *a == *b) { a++; b++; n--; }
    return n ? (int)(uint8_t)*a - (int)(uint8_t)*b : 0;
}
char *nrf70_os_strchr(const char *s, int c) {
    for (;; s++) { if (*s == (char)c) return (char *)s; if (!*s) return NULL; }
}
char *nrf70_os_strrchr(const char *s, int c) {
    const char *r = NULL;
    for (;; s++) { if (*s == (char)c) r = s; if (!*s) return (char *)r; }
}
char *nrf70_os_strstr(const char *h, const char *n) {
    size_t l = nrf70_os_strlen(n);
    if (!l) return (char *)h;
    for (; *h; h++) if (!nrf70_os_strncmp(h, n, l)) return (char *)h;
    return NULL;
}
static int digit_val(char c) { return c >= '0' && c <= '9' ? c - '0' : -1; }
int nrf70_os_atoi(const char *s) {
    int v = 0, neg = 0;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '-') { neg = 1; s++; } else if (*s == '+') s++;
    for (; digit_val(*s) >= 0; s++) v = v * 10 + digit_val(*s);
    return neg ? -v : v;
}
long nrf70_os_strtol(const char *s, char **end, int base) {
    long v = 0; int neg = 0;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '-') { neg = 1; s++; } else if (*s == '+') s++;
    if ((base == 0 || base == 16) && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) { base = 16; s += 2; }
    if (base == 0) base = s[0] == '0' ? 8 : 10;
    for (;; s++) {
        int d = digit_val(*s);
        if (d < 0 && *s >= 'a' && *s <= 'z') d = *s - 'a' + 10;
        if (d < 0 && *s >= 'A' && *s <= 'Z') d = *s - 'A' + 10;
        if (d < 0 || d >= base) break;
        v = v * base + d;
    }
    if (end) *end = (char *)s;
    return neg ? -v : v;
}
/* Debug-only helpers format through vsnprintf; emit an empty string. */
int nrf70_os_vsnprintf(char *dst, size_t n, const char *fmt, va_list ap) {
    (void)fmt; (void)ap;
    if (dst && n) dst[0] = 0;
    return -1;
}
void nrf70_os_qsort(void *base, size_t nmemb, size_t size,
                    int (*cmp)(const void *, const void *)) {
    uint8_t *a = base, tmp[16];
    if (size > sizeof(tmp)) return; /* only int-sized helper arrays exist here */
    for (size_t i = 1; i < nmemb; i++) {
        nrf70_os_memcpy(tmp, a + i * size, size);
        size_t j = i;
        while (j && cmp(a + (j - 1) * size, tmp) > 0) { nrf70_os_memcpy(a + j * size, a + (j - 1) * size, size); j--; }
        nrf70_os_memcpy(a + j * size, tmp, size);
    }
}
void nrf70_os_abort(void) { for (;;) { } } /* wpabuf overflow guard; unreachable */

/* os_* shims; os.h maps the rest to the interposed libc set. */
void *os_zalloc(size_t size) {
    void *p = nrf70_os_malloc(size);
    if (p) nrf70_os_memset(p, 0, size);
    return p;
}
void *os_memdup(const void *src, size_t len) {
    void *p = nrf70_os_malloc(len);
    if (p && src) nrf70_os_memcpy(p, src, len);
    return p;
}
int os_memcmp_const(const void *a, const void *b, size_t len) {
    const uint8_t *aa = a, *bb = b;
    uint8_t res = 0;
    for (size_t i = 0; i < len; i++) res |= aa[i] ^ bb[i];
    return res;
}
int os_get_random(unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) buf[i] = nrf70_supp_host_random_u8();
    return 0;
}
int os_get_time(struct os_time *t) {
    uint32_t us = nrf70_supp_host_now_us();
    t->sec = (os_time_t)(us / 1000000u);
    t->usec = (os_time_t)(us % 1000000u);
    return 0;
}
int os_get_reltime(struct os_reltime *t) {
    uint32_t us = nrf70_supp_host_now_us();
    t->sec = (os_time_t)(us / 1000000u);
    t->usec = (os_time_t)(us % 1000000u);
    return 0;
}

/* Mini-eloop: only the two entry points the subset references. With
 * wpa_ptk_rekey unset these slots stay empty. */
#define SUPP_ELOOP_SLOTS 4u
struct supp_timeout {
    uint8_t used;
    uint32_t deadline_us;
    eloop_timeout_handler handler;
    void *eloop_data, *user_data;
};
static struct supp_timeout supp_timeouts[SUPP_ELOOP_SLOTS];

int eloop_register_timeout(unsigned int secs, unsigned int usecs,
                           eloop_timeout_handler handler,
                           void *eloop_data, void *user_data) {
    for (unsigned i = 0; i < SUPP_ELOOP_SLOTS; i++) {
        struct supp_timeout *t = &supp_timeouts[i];
        if (t->used) continue;
        t->used = 1;
        t->deadline_us = nrf70_supp_host_now_us() + secs * 1000000u + usecs;
        t->handler = handler; t->eloop_data = eloop_data; t->user_data = user_data;
        return 0;
    }
    return -1;
}
int eloop_cancel_timeout(eloop_timeout_handler handler, void *eloop_data, void *user_data) {
    int removed = 0;
    for (unsigned i = 0; i < SUPP_ELOOP_SLOTS; i++) {
        struct supp_timeout *t = &supp_timeouts[i];
        if (t->used && t->handler == handler &&
            (eloop_data == ELOOP_ALL_CTX || t->eloop_data == eloop_data) &&
            (user_data == ELOOP_ALL_CTX || t->user_data == user_data)) {
            t->used = 0;
            removed++;
        }
    }
    return removed;
}
uint32_t nrf70_supp_eloop_poll(uint32_t now_us) {
    uint32_t ran = 0;
    for (unsigned i = 0; i < SUPP_ELOOP_SLOTS; i++) {
        struct supp_timeout *t = &supp_timeouts[i];
        if (t->used && (int32_t)(now_us - t->deadline_us) >= 0) {
            eloop_timeout_handler h = t->handler;
            void *e = t->eloop_data, *u = t->user_data;
            t->used = 0;
            if (h) h(e, u);
            ran++;
        }
    }
    return ran;
}
uint32_t nrf70_supp_eloop_next_us(uint32_t now_us) {
    uint32_t next = UINT32_MAX;
    for (unsigned i = 0; i < SUPP_ELOOP_SLOTS; i++) {
        struct supp_timeout *t = &supp_timeouts[i];
        if (!t->used) continue;
        int32_t left = (int32_t)(t->deadline_us - now_us);
        if (left <= 0) return 0;
        if ((uint32_t)left < next) next = (uint32_t)left;
    }
    return next;
}

/* Sliced PBKDF2-SHA1 (RFC 2898): 4096 iterations, two 20-byte blocks for the
 * 32-byte PMK. hostap's one-shot pbkdf2_sha1 would block for tens of ms. */
struct pbkdf2_state {
    uint8_t active, block, pass_len, ssid_len;
    uint16_t iter;
    uint8_t pass[63], ssid[32];
    uint8_t u[SHA1_MAC_LEN], t[SHA1_MAC_LEN], out[2 * SHA1_MAC_LEN];
};
static struct pbkdf2_state pbkdf2;

int32_t nrf70_supp_pbkdf2_start(const uint8_t *passphrase, uint8_t passphrase_len,
                                const uint8_t *ssid, uint8_t ssid_len) {
    if (!passphrase || passphrase_len < 8 || passphrase_len > 63 ||
        !ssid || !ssid_len || ssid_len > 32)
        return -1;
    forced_memzero(&pbkdf2, sizeof(pbkdf2));
    nrf70_os_memcpy(pbkdf2.pass, passphrase, passphrase_len);
    pbkdf2.pass_len = passphrase_len;
    nrf70_os_memcpy(pbkdf2.ssid, ssid, ssid_len);
    pbkdf2.ssid_len = ssid_len;
    pbkdf2.block = 1;
    pbkdf2.active = 1;
    return 0;
}
int32_t nrf70_supp_pbkdf2_step(uint8_t pmk_out[NRF70_SUPP_PMK_LEN]) {
    if (!pbkdf2.active || !pmk_out) return -1;
    uint32_t budget = NRF70_SUPP_PBKDF2_SLICE_ITERS;
    while (budget) {
        if (pbkdf2.iter == 0) {
            uint8_t salt[36];
            nrf70_os_memcpy(salt, pbkdf2.ssid, pbkdf2.ssid_len);
            salt[pbkdf2.ssid_len] = 0; salt[pbkdf2.ssid_len + 1] = 0;
            salt[pbkdf2.ssid_len + 2] = 0; salt[pbkdf2.ssid_len + 3] = pbkdf2.block;
            if (hmac_sha1(pbkdf2.pass, pbkdf2.pass_len, salt,
                          (size_t)pbkdf2.ssid_len + 4, pbkdf2.u))
                return -1;
            nrf70_os_memcpy(pbkdf2.t, pbkdf2.u, SHA1_MAC_LEN);
            pbkdf2.iter = 1;
            budget--;
            continue;
        }
        while (budget && pbkdf2.iter < 4096) {
            if (hmac_sha1(pbkdf2.pass, pbkdf2.pass_len, pbkdf2.u, SHA1_MAC_LEN, pbkdf2.u))
                return -1;
            for (unsigned i = 0; i < SHA1_MAC_LEN; i++) pbkdf2.t[i] ^= pbkdf2.u[i];
            pbkdf2.iter++;
            budget--;
        }
        if (pbkdf2.iter == 4096) {
            nrf70_os_memcpy(&pbkdf2.out[(pbkdf2.block - 1u) * SHA1_MAC_LEN],
                            pbkdf2.t, SHA1_MAC_LEN);
            if (pbkdf2.block == 2) {
                nrf70_os_memcpy(pmk_out, pbkdf2.out, NRF70_SUPP_PMK_LEN);
                forced_memzero(&pbkdf2, sizeof(pbkdf2));
                return 1;
            }
            pbkdf2.block = 2;
            pbkdf2.iter = 0;
        }
    }
    return 0;
}

static struct wpa_sm *supp_sm;
static enum wpa_states supp_state;
static uint8_t supp_bssid[6], supp_own_addr[6];
static uint8_t supp_completed_once;
static int supp_network_ctx; /* fixed identity token for get_network_ctx */

static void supp_set_state(void *ctx, enum wpa_states state) {
    (void)ctx;
    supp_state = state;
    if (state == WPA_COMPLETED) {
        nrf70_supp_host_completed(supp_completed_once);
        supp_completed_once = 1;
    }
}
static enum wpa_states supp_get_state(void *ctx) { (void)ctx; return supp_state; }
static void supp_deauthenticate(void *ctx, u16 reason_code) {
    (void)ctx;
    nrf70_supp_host_deauth(reason_code);
}
static void supp_reconnect(void *ctx) { (void)ctx; } /* deny_ptk0_rekey unset */
static int supp_set_key(void *ctx, int link_id, enum wpa_alg alg, const u8 *addr,
                        int key_idx, int set_tx, const u8 *seq, size_t seq_len,
                        const u8 *key, size_t key_len, enum key_flag key_flag) {
    (void)ctx; (void)link_id; (void)set_tx; (void)key_flag;
    if (alg == WPA_ALG_NONE) return 0; /* key removal: ignored gracefully */
    if (alg == WPA_ALG_CCMP) {
        uint8_t pairwise = addr && os_memcmp_const(addr, supp_bssid, 6) == 0 &&
                           !(addr[0] & 1);
        return nrf70_supp_host_add_key(pairwise, pairwise ? addr : NULL,
                                       (uint8_t)key_idx, 0x000FAC04u, key,
                                       (uint16_t)key_len, seq, (uint16_t)seq_len,
                                       0) == 0 ? 0 : -1;
    }
    if (alg == WPA_ALG_BIP_CMAC_128)
        return nrf70_supp_host_add_key(0, NULL, (uint8_t)key_idx, 0x000FAC06u,
                                       key, (uint16_t)key_len, seq,
                                       (uint16_t)seq_len, 1) == 0 ? 0 : -1;
    return -1; /* TKIP/GCMP/... are compiled out of this build */
}
static void *supp_get_network_ctx(void *ctx) { (void)ctx; return &supp_network_ctx; }
static int supp_get_bssid(void *ctx, u8 *bssid) {
    (void)ctx;
    nrf70_os_memcpy(bssid, supp_bssid, 6);
    return 0;
}
static int supp_ether_send(void *ctx, const u8 *dest, u16 proto, const u8 *buf, size_t len) {
    (void)ctx;
    return (int)nrf70_supp_host_ether_send(dest, proto, buf, len);
}
static int supp_get_beacon_ie(void *ctx) { (void)ctx; return -1; } /* IE set up front */
static void supp_cancel_auth_timeout(void *ctx) { (void)ctx; }
static u8 *supp_alloc_eapol(void *ctx, u8 type, const void *data, u16 data_len,
                            size_t *msg_len, void **data_pos) {
    (void)ctx;
    struct ieee802_1x_hdr *hdr;
    *msg_len = sizeof(*hdr) + data_len;
    hdr = nrf70_os_malloc(*msg_len);
    if (!hdr) return NULL;
    hdr->version = EAPOL_VERSION;
    hdr->type = type;
    hdr->length = host_to_be16(data_len);
    if (data) nrf70_os_memcpy(hdr + 1, data, data_len);
    else nrf70_os_memset(hdr + 1, 0, data_len);
    if (data_pos) *data_pos = hdr + 1;
    return (u8 *)hdr;
}
static int supp_mlme_setprotection(void *ctx, const u8 *addr, int protection_type,
                                   int key_type) {
    (void)ctx; (void)addr; (void)protection_type; (void)key_type;
    return 0; /* FullMAC firmware enables protection with the installed keys */
}

int32_t nrf70_supp_start(const uint8_t own_addr[6], const uint8_t bssid[6],
                         const uint8_t pmk[NRF70_SUPP_PMK_LEN], uint8_t mfp,
                         uint8_t akm_sha256,
                         const uint8_t *ap_rsn_ie, uint16_t ap_rsn_ie_len,
                         const uint8_t *ap_rsnxe, uint16_t ap_rsnxe_len,
                         uint8_t *assoc_ie_out, uint16_t *assoc_ie_len) {
    struct wpa_sm_ctx *ctx;
    size_t ie_len;
    if (supp_sm || !own_addr || !bssid || !pmk || !ap_rsn_ie || !ap_rsn_ie_len ||
        !assoc_ie_out || !assoc_ie_len)
        return -1;
    ctx = os_zalloc(sizeof(*ctx)); /* wpa_sm_deinit frees this */
    if (!ctx) return -1;
    ctx->set_state = supp_set_state;
    ctx->get_state = supp_get_state;
    ctx->deauthenticate = supp_deauthenticate;
    ctx->reconnect = supp_reconnect;
    ctx->set_key = supp_set_key;
    ctx->get_network_ctx = supp_get_network_ctx;
    ctx->get_bssid = supp_get_bssid;
    ctx->ether_send = supp_ether_send;
    ctx->get_beacon_ie = supp_get_beacon_ie;
    ctx->cancel_auth_timeout = supp_cancel_auth_timeout;
    ctx->alloc_eapol = supp_alloc_eapol;
    ctx->mlme_setprotection = supp_mlme_setprotection;
    supp_sm = wpa_sm_init(ctx);
    if (!supp_sm) {
        nrf70_os_free(ctx);
        return -1;
    }
    supp_state = WPA_ASSOCIATING;
    supp_completed_once = 0;
    nrf70_os_memcpy(supp_own_addr, own_addr, 6);
    nrf70_os_memcpy(supp_bssid, bssid, 6);
    wpa_sm_set_own_addr(supp_sm, supp_own_addr);
    wpa_sm_set_param(supp_sm, WPA_PARAM_RSN_ENABLED, 1);
    wpa_sm_set_param(supp_sm, WPA_PARAM_PROTO, WPA_PROTO_RSN);
    wpa_sm_set_param(supp_sm, WPA_PARAM_PAIRWISE, WPA_CIPHER_CCMP);
    wpa_sm_set_param(supp_sm, WPA_PARAM_GROUP, WPA_CIPHER_CCMP);
    wpa_sm_set_param(supp_sm, WPA_PARAM_KEY_MGMT,
                     akm_sha256 ? WPA_KEY_MGMT_PSK_SHA256 : WPA_KEY_MGMT_PSK);
    wpa_sm_set_param(supp_sm, WPA_PARAM_MFP, mfp > 2 ? 0 : mfp);
    /* With MFP enabled the AP delivers an IGTK in msg3/group rekeys; the
     * management group cipher must be set or ieee80211w_set_keys() silently
     * discards it and BIP protection never activates. */
    if (mfp > 0)
        wpa_sm_set_param(supp_sm, WPA_PARAM_MGMT_GROUP, WPA_CIPHER_AES_128_CMAC);
    wpa_sm_set_pmk(supp_sm, pmk, NRF70_SUPP_PMK_LEN, NULL, NULL);
    if (wpa_sm_set_ap_rsn_ie(supp_sm, ap_rsn_ie, ap_rsn_ie_len))
        goto fail;
    if (ap_rsnxe && ap_rsnxe_len &&
        wpa_sm_set_ap_rsnxe(supp_sm, ap_rsnxe, ap_rsnxe_len))
        goto fail;
    ie_len = *assoc_ie_len;
    if (wpa_sm_set_assoc_wpa_ie_default(supp_sm, assoc_ie_out, &ie_len))
        goto fail;
    *assoc_ie_len = (uint16_t)ie_len;
    return 0;
fail:
    nrf70_supp_stop();
    return -1;
}
void nrf70_supp_notify_assoc(const uint8_t bssid[6]) {
    if (!supp_sm) return;
    nrf70_os_memcpy(supp_bssid, bssid, 6);
    wpa_sm_notify_assoc(supp_sm, bssid);
}
void nrf70_supp_rx_eapol(const uint8_t src[6], const uint8_t *frame, uint16_t len) {
    if (!supp_sm) return;
    wpa_sm_rx_eapol(supp_sm, src, frame, len, FRAME_ENCRYPTION_UNKNOWN);
}
void nrf70_supp_stop(void) {
    if (supp_sm) {
        wpa_sm_notify_disassoc(supp_sm); /* drops the SA and zeroizes keys */
        wpa_sm_deinit(supp_sm);          /* frees sm and its ctx */
        supp_sm = NULL;
    }
    nrf70_supp_clear_secrets();
    nrf70_os_memset(supp_timeouts, 0, sizeof(supp_timeouts));
    nrf70_os_memset(supp_bssid, 0, sizeof(supp_bssid));
    supp_state = WPA_DISCONNECTED;
    supp_completed_once = 0;
}
void nrf70_supp_clear_secrets(void) { forced_memzero(&pbkdf2, sizeof(pbkdf2)); }
uint8_t nrf70_supp_active(void) { return supp_sm != NULL; }
