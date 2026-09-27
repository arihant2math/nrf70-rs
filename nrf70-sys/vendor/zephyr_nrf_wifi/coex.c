/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 * @brief Coexistence functions
 *
 * Derived from zephyr `drivers/wifi/nrf_wifi/src/coex.c` (upstream commit
 * and SHA-256 in vendor-manifest.toml). Modifications for the nrf70-sys
 * facade, which has no Zephyr kernel, devicetree, or driver globals:
 *
 *   - the Zephyr headers, logging, and the `rpu_drv_priv_zep` global are
 *     gone; every entry point takes the FMAC device context instead;
 *   - the shared-antenna tables (`config_buffer_SHA`, `ch_config_sha`) and
 *     the SR RF-switch GPIO code (`CONFIG_NRF70_SR_COEX_RF_SWITCH`) are
 *     dropped: the nRF54LM20A and nRF7002 each drive their own antenna;
 *   - `separate_antennas` is therefore no longer a parameter;
 *   - the functions are prefixed `nrf70_coex_` and declared in coex.h.
 *
 * The register offsets, the PTA lookup tables, and the non-PTA channel
 * configuration values are byte-for-byte the upstream ones.
 */

#include <stdint.h>
#include <stdbool.h>

#include "coex.h"
#include "coex_struct.h"
#include "common/fmac_api_common.h"

#define CH_BASE_ADDRESS ABS_EXT_SYS_WLANSYSCOEX_CH_CONTROL
#define COEX_CONFIG_FIXED_PARAMS 4
#define COEX_REG_CFG_OFFSET_SHIFT 24

/* copied from uccp530_77_registers_ext_sys_bus.h of UCCP toolkit */
#define EXT_SYS_WLANSYSCOEX_CH_CONTROL 0x0000
#define ABS_EXT_SYS_WLANSYSCOEX_CH_CONTROL 0xA401BC00UL
#define EXT_SYS_WLANSYSCOEX_CH_TIME_REFERENCE 0x0004
#define EXT_SYS_WLANSYSCOEX_CH_SR_INFO_STATUS 0x0040
#define EXT_SYS_WLANSYSCOEX_CH_NO_WINDOW_LOOKUP_0 0x008C
#define EXT_SYS_WLANSYSCOEX_CH_NO_WINDOW_LOOKUP_44 0x013C
#define EXT_SYS_WLANSYSCOEX_RESET_SHIFT 0

/* PTA registers configuration of Coexistence Hardware */
/* Separate antenna configuration, WLAN in 2.4GHz. For BLE protocol. */
static const uint16_t config_buffer_SEA_ble[] = {
	0x0019, 0x00F6, 0x0008, 0x0062, 0x00F5,
	0x00F5, 0x0019, 0x0019, 0x0074, 0x0074,
	0x0008, 0x01E2, 0x00D5, 0x00D5, 0x01F6,
	0x01F6, 0x0061, 0x0061, 0x01E2, 0x0008,
	0x0004, 0x0004, 0x0019, 0x0019, 0x0008,
	0x0008, 0x00F5, 0x00F5, 0x00D5, 0x00D5,
	0x0008, 0x01E2, 0x0051, 0x0051, 0x0074,
	0x0074, 0x00F6, 0x0019, 0x0062, 0x0019,
	0x00F6, 0x0008, 0x0062, 0x0008, 0x001A
};

/* Separate antenna configuration, WLAN in 2.4GHz. For non BLE protocol */
static const uint16_t config_buffer_SEA_non_ble[] = {
	0x0019, 0x00F6, 0x0008, 0x0062, 0x00F5,
	0x00F5, 0x0061, 0x0061, 0x0074, 0x0074,
	0x01E2, 0x01E2, 0x00D5, 0x00D5, 0x01F6,
	0x01F6, 0x0061, 0x0061, 0x01E2, 0x01E2,
	0x00C4, 0x00C4, 0x0061, 0x0061, 0x0008,
	0x0008, 0x00F5, 0x00F5, 0x00D5, 0x00D5,
	0x0162, 0x0162, 0x0019, 0x0019, 0x01F6,
	0x01F6, 0x00F6, 0x0019, 0x0062, 0x0019,
	0x00F6, 0x0008, 0x0062, 0x0008, 0x001A
};

/* Shared/separate antennas, WLAN in 5GHz */
static const uint16_t config_buffer_5G[] = {
	0x0039, 0x0076, 0x0028, 0x0062, 0x0075,
	0x0075, 0x0061, 0x0061, 0x0074, 0x0074,
	0x0060, 0x0060, 0x0075, 0x0075, 0x0064,
	0x0064, 0x0071, 0x0071, 0x0060, 0x0060,
	0x0064, 0x0064, 0x0061, 0x0061, 0x0060,
	0x0060, 0x0075, 0x0075, 0x0075, 0x0075,
	0x0060, 0x0060, 0x0071, 0x0071, 0x0074,
	0x0074, 0x0076, 0x0039, 0x0062, 0x0039,
	0x0076, 0x0028, 0x0062, 0x0028, 0x003A
};

/* non-PTA register configuration of coexistence hardware */
/* Separate antennas. For BLE protocol. */
static const uint32_t ch_config_sep_ble[] = {
	0x00000028, 0x00000000, 0x001e1023, 0x00000000, 0x00000000,
	0x00000000, 0x00000021, 0x000002ca, 0x00000055, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000
};

/* Separate antennas. For non BLE protocol. */
static const uint32_t ch_config_sep_non_ble[] = {
	0x00000028, 0x00000000, 0x001e1023, 0x00000000, 0x00000000,
	0x00000000, 0x00000021, 0x000002ca, 0x00000055, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000
};

int nrf70_coex_config_non_pta(struct nrf_wifi_fmac_dev_ctx *fmac_dev_ctx,
			      bool is_sr_protocol_ble)
{
	enum nrf_wifi_status status = NRF_WIFI_STATUS_FAIL;
	struct coex_ch_configuration params  = { 0 };
	const uint32_t *config_buffer_ptr = NULL;
	uint32_t start_offset = 0;
	uint32_t num_reg_to_config = 1;
	uint32_t cmd_len, index;

	/* Offset from the base address of CH */
	start_offset = ((EXT_SYS_WLANSYSCOEX_CH_TIME_REFERENCE -
	EXT_SYS_WLANSYSCOEX_CH_CONTROL) >> 2);
	/* Number of registers to be configured */
	num_reg_to_config = ((EXT_SYS_WLANSYSCOEX_CH_SR_INFO_STATUS -
	EXT_SYS_WLANSYSCOEX_CH_TIME_REFERENCE) >> 2) + 1;

	if (is_sr_protocol_ble) {
		config_buffer_ptr = ch_config_sep_ble;
	} else {
		config_buffer_ptr = ch_config_sep_non_ble;
	}

	params.message_id = HW_CONFIGURATION;
	params.num_reg_to_config = num_reg_to_config;
	params.hw_to_config = COEX_HARDWARE;
	params.hw_block_base_addr = CH_BASE_ADDRESS;

	for (index = 0; index < num_reg_to_config; index++) {
		params.configbuf[index] = (start_offset << COEX_REG_CFG_OFFSET_SHIFT) |
			(*(config_buffer_ptr + index));
		start_offset++;
	}

	cmd_len = (COEX_CONFIG_FIXED_PARAMS + num_reg_to_config) * sizeof(uint32_t);
	status = nrf_wifi_fmac_conf_srcoex(fmac_dev_ctx,
					   (void *)(&params), cmd_len);
	if (status != NRF_WIFI_STATUS_SUCCESS) {
		return -1;
	}

	return 0;
}

int nrf70_coex_config_pta(struct nrf_wifi_fmac_dev_ctx *fmac_dev_ctx,
			  enum nrf70_coex_wlan_op_band wlan_band,
			  bool is_sr_protocol_ble)
{
	enum nrf_wifi_status status = NRF_WIFI_STATUS_FAIL;
	struct coex_ch_configuration params  = { 0 };
	const uint16_t *config_buffer_ptr = NULL;
	uint32_t start_offset = 0;
	uint32_t num_reg_to_config = 1;
	uint32_t cmd_len, index;

	/* Indicates offset from the base address of CH */
	start_offset = ((EXT_SYS_WLANSYSCOEX_CH_NO_WINDOW_LOOKUP_0 -
	EXT_SYS_WLANSYSCOEX_CH_CONTROL) >> 2);
	/* Number of contiguous registers to be configured starting from base+offset */
	num_reg_to_config = ((EXT_SYS_WLANSYSCOEX_CH_NO_WINDOW_LOOKUP_44 -
	EXT_SYS_WLANSYSCOEX_CH_NO_WINDOW_LOOKUP_0) >> 2) + 1;

	if (wlan_band == NRF70_COEX_WLAN_OP_BAND_2_4_GHZ) {
		/* WLAN operating in 2.4GHz, separate antennas */
		if (is_sr_protocol_ble) {
			config_buffer_ptr = config_buffer_SEA_ble;
		} else {
			config_buffer_ptr = config_buffer_SEA_non_ble;
		}
	} else if (wlan_band == NRF70_COEX_WLAN_OP_BAND_5_GHZ) {
		/* WLAN operating in 5GHz */
		config_buffer_ptr = config_buffer_5G;
	} else {
		return -2;
	}

	params.message_id = HW_CONFIGURATION;
	params.num_reg_to_config = num_reg_to_config;
	params.hw_to_config = COEX_HARDWARE;
	params.hw_block_base_addr = CH_BASE_ADDRESS;

	for (index = 0; index < num_reg_to_config; index++) {
		params.configbuf[index] = (start_offset << COEX_REG_CFG_OFFSET_SHIFT) |
			(*(config_buffer_ptr+index));
		start_offset++;
	}

	cmd_len = (COEX_CONFIG_FIXED_PARAMS + num_reg_to_config) * sizeof(uint32_t);
	status = nrf_wifi_fmac_conf_srcoex(fmac_dev_ctx,
					   (void *)(&params), cmd_len);
	if (status != NRF_WIFI_STATUS_SUCCESS) {
		return -1;
	}

	return 0;
}

int nrf70_coex_hw_reset(struct nrf_wifi_fmac_dev_ctx *fmac_dev_ctx)
{
	enum nrf_wifi_status status = NRF_WIFI_STATUS_FAIL;
	struct coex_ch_configuration params  = { 0 };
	uint32_t num_reg_to_config = 1;
	uint32_t start_offset = 0;
	uint32_t index = 0;
	uint32_t coex_hw_reset = 1;
	uint32_t cmd_len;

	/* reset CH */
	params.message_id = HW_CONFIGURATION;
	params.num_reg_to_config = num_reg_to_config;
	params.hw_to_config = COEX_HARDWARE;
	params.hw_block_base_addr = CH_BASE_ADDRESS;

	start_offset = ((EXT_SYS_WLANSYSCOEX_CH_CONTROL - EXT_SYS_WLANSYSCOEX_CH_CONTROL) >> 2);
	params.configbuf[index] = (start_offset << COEX_REG_CFG_OFFSET_SHIFT) |
	(coex_hw_reset << EXT_SYS_WLANSYSCOEX_RESET_SHIFT);

	cmd_len = (COEX_CONFIG_FIXED_PARAMS + num_reg_to_config) * sizeof(uint32_t);

	status = nrf_wifi_fmac_conf_srcoex(fmac_dev_ctx,
				(void *)(&params), cmd_len);

	if (status != NRF_WIFI_STATUS_SUCCESS) {
		return -1;
	}

	return 0;
}
