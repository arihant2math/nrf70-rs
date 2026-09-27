/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @brief Header containing Coexistence APIs.
 *
 * Derived from zephyr `drivers/wifi/nrf_wifi/inc/coex.h` for the nrf70-sys
 * facade: the entry points take the FMAC device context instead of reading
 * a Zephyr driver global, the `separate_antennas` parameter and the SR
 * RF-switch API are gone (separate antennas only), and the names carry an
 * `nrf70_coex_` prefix. See coex.c for the table provenance.
 */

#ifndef __NRF70_COEX_H__
#define __NRF70_COEX_H__

#include <stdbool.h>

struct nrf_wifi_fmac_dev_ctx;

/* Indicates WLAN frequency band of operation */
enum nrf70_coex_wlan_op_band {
	NRF70_COEX_WLAN_OP_BAND_2_4_GHZ = 0,
	NRF70_COEX_WLAN_OP_BAND_5_GHZ,
	NRF70_COEX_WLAN_OP_BAND_NONE = 0xFF
};

/**
 * @brief      Function used to configure PTA tables of coexistence hardware
 *             (separate antennas).
 *
 * @param[in]  fmac_dev_ctx  FMAC device context of the RPU.
 * @param[in]  wlan_band     Band the station operates on.
 * @param[in]  is_sr_protocol_ble
 *             Indicates if SR protocol is Bluetooth LE or not.
 * @return     Returns zero upon successful configuration, -1 when the RPU
 *             command could not be sent, -2 for an unknown band.
 */
int nrf70_coex_config_pta(struct nrf_wifi_fmac_dev_ctx *fmac_dev_ctx,
			  enum nrf70_coex_wlan_op_band wlan_band,
			  bool is_sr_protocol_ble);

/**
 * @brief      Function used to configure non-PTA registers of coexistence
 *             hardware (separate antennas).
 *
 * @param[in]  fmac_dev_ctx  FMAC device context of the RPU.
 * @param[in]  is_sr_protocol_ble
 *             Indicates if SR protocol is Bluetooth LE or not.
 * @return     Returns zero upon successful configuration, non-zero otherwise.
 */
int nrf70_coex_config_non_pta(struct nrf_wifi_fmac_dev_ctx *fmac_dev_ctx,
			      bool is_sr_protocol_ble);

/**
 * @brief      Function used to reset coexistence hardware.
 *
 * @param[in]  fmac_dev_ctx  FMAC device context of the RPU.
 * @return     Returns zero upon successful configuration, non-zero otherwise.
 */
int nrf70_coex_hw_reset(struct nrf_wifi_fmac_dev_ctx *fmac_dev_ctx);

#endif /* __NRF70_COEX_H__ */
