/* SPDX-License-Identifier: BSD-3-Clause */
/* Internal contract between facade.c and supplicant.c. NOT part of the Rust ABI.
 * facade.c never includes hostap headers; supplicant.c never includes nrf_wifi
 * headers. Everything crosses this boundary as plain C types. All functions run
 * on the serialized Wi-Fi context: the supp_* entry points are called only from
 * nrf70_facade_process() top level, and the nrf70_supp_host_* hooks are called
 * only from inside those supp_* calls, so they may re-enter FMAC directly. */
#ifndef NRF70_SUPPLICANT_H
#define NRF70_SUPPLICANT_H

#include <stddef.h>
#include <stdint.h>

#define NRF70_SUPP_PMK_LEN 32u
#define NRF70_SUPP_ASSOC_IE_MAX 64u
#define NRF70_SUPP_PBKDF2_SLICE_ITERS 256u

/* --- implemented in supplicant.c, called by facade.c --- */

/* Sliced PBKDF2-SHA1 (4096 iterations, 2 blocks). start copies and owns a
 * zeroized-on-completion staging copy of the passphrase. */
int32_t nrf70_supp_pbkdf2_start(const uint8_t *passphrase, uint8_t passphrase_len,
                                const uint8_t *ssid, uint8_t ssid_len);
/* Advances at most NRF70_SUPP_PBKDF2_SLICE_ITERS HMAC iterations.
 * Returns 0 while in progress, 1 when pmk_out is filled (staging zeroized),
 * negative on misuse. */
int32_t nrf70_supp_pbkdf2_step(uint8_t pmk_out[NRF70_SUPP_PMK_LEN]);

/* Creates the wpa_sm session (WPA2-PSK/CCMP, RSN only), installs the PMK and
 * the AP RSN IE (and RSNXE when present), and emits the association RSN IE to
 * assoc_ie_out (capacity NRF70_SUPP_ASSOC_IE_MAX, *assoc_ie_len in/out).
 * akm_sha256!=0 selects the PSK-SHA256 AKM (00-0F-AC:6) instead of plain PSK;
 * mfp>0 additionally enables the BIP-CMAC-128 management group cipher so the
 * IGTK from msg3/group rekeys is installed. The caller zeroizes its pmk copy
 * after this returns. */
int32_t nrf70_supp_start(const uint8_t own_addr[6], const uint8_t bssid[6],
                         const uint8_t pmk[NRF70_SUPP_PMK_LEN], uint8_t mfp,
                         uint8_t akm_sha256,
                         const uint8_t *ap_rsn_ie, uint16_t ap_rsn_ie_len,
                         const uint8_t *ap_rsnxe, uint16_t ap_rsnxe_len,
                         uint8_t *assoc_ie_out, uint16_t *assoc_ie_len);
void nrf70_supp_notify_assoc(const uint8_t bssid[6]);
/* frame points at the 802.1X header (Ethernet header already stripped). */
void nrf70_supp_rx_eapol(const uint8_t src[6], const uint8_t *frame, uint16_t len);
/* Runs expired mini-eloop timeouts. Returns the number of handlers run. */
uint32_t nrf70_supp_eloop_poll(uint32_t now_us);
/* wpa_sm_deinit (zeroizes the PMK/PTK inside wpa_sm) + clears all staging. */
void nrf70_supp_stop(void);
/* Zeroizes only the static secret staging (PBKDF2 state). Safe to call from
 * fatal paths that may be nested inside a wpa_sm call; never frees memory. */
void nrf70_supp_clear_secrets(void);
uint8_t nrf70_supp_active(void);

/* --- implemented in facade.c, called by supplicant.c --- */

uint32_t nrf70_supp_host_now_us(void);
uint8_t nrf70_supp_host_random_u8(void);
/* pairwise!=0: peer is the BSSID, KEYTYPE_PAIRWISE. pairwise==0: group key,
 * installed with a NULL MAC and then set as the default multicast key
 * (is_mgmt!=0 marks an IGTK: default management key instead). seq is the
 * little-endian RSC (6 bytes for CCMP) or empty. */
int32_t nrf70_supp_host_add_key(uint8_t pairwise, const uint8_t peer[6],
                                uint8_t key_idx, uint32_t cipher_suite,
                                const uint8_t *key, uint16_t key_len,
                                const uint8_t *seq, uint16_t seq_len,
                                uint8_t is_mgmt);
/* Builds dst/src/proto Ethernet header around buf and transmits through the
 * normal FMAC data path (this pin has no control-port TX command). Does not
 * require the data link to be up. */
int32_t nrf70_supp_host_ether_send(const uint8_t dst[6], uint16_t proto,
                                   const uint8_t *buf, size_t len);
/* Handshake failure: emits HANDSHAKE_FAILED, deauthenticates the radio, and
 * schedules supplicant teardown for the next process() step. */
void nrf70_supp_host_deauth(uint16_t reason_code);
/* WPA_COMPLETED: authorizes the controlled port (rekey==0) or counts a rekey. */
void nrf70_supp_host_completed(uint8_t rekey);

#endif
