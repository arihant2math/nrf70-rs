use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const TARGET: &str = "thumbv8m.main-none-eabihf";
const CLANG_MAJOR_VERSION: &str = "21";
const BLOB_SHA256: &str = "36b84d10037a9609a2a0fe86a0ef5b53fcd5fc2e88621c6d8f0f711b76775b1e";
const LICENSE_SHA256: &str = "47d92141c69e74a0166c319a41e5005ce2b87f0498e5dbd5a0c5a34f9ef63954";
const NRF70_BM_REV: &str = "185ec021afb61dc2d42b4f65800c3aa3d27c88d6";
const NRF_WIFI_REV: &str = "0aaa9aa812877cb6bc020df8260d0607a3f0ec1a";
const NRFXLIB_REV: &str = "f1591c62b301c2dc8d91308d43903de563f64d81";
const HOSTAP_REV: &str = "d467a115b8fc20b8b7120937cb1d445dacebc6a1";
/// zephyr `drivers/wifi/nrf_wifi/inc/coex_struct.h`, vendored verbatim; the
/// commit is in vendor-manifest.toml.
const COEX_STRUCT_SHA256: &str = "de3107a4f32f351ec990be3e6e3c386d8e7ffba99f9eaea4f3cff3d5ca3cf6b5";

const SOURCES: &[&str] = &[
    "nrf70_bm_lib/source/common/nrf70_bm_core.c",
    "nrf_wifi/os_if/src/osal.c",
    "nrf_wifi/utils/src/list.c",
    "nrf_wifi/utils/src/queue.c",
    "nrf_wifi/utils/src/util.c",
    "nrf_wifi/hw_if/hal/src/common/hal_api_common.c",
    "nrf_wifi/hw_if/hal/src/common/hal_fw_patch_loader.c",
    "nrf_wifi/hw_if/hal/src/common/hal_interrupt.c",
    "nrf_wifi/hw_if/hal/src/common/hal_mem.c",
    "nrf_wifi/hw_if/hal/src/common/hal_reg.c",
    "nrf_wifi/hw_if/hal/src/common/hpqm.c",
    "nrf_wifi/hw_if/hal/src/common/pal.c",
    "nrf_wifi/bus_if/bal/src/bal.c",
    "nrf_wifi/bus_if/bus/qspi/src/qspi.c",
    "nrf_wifi/fw_if/umac_if/src/common/fmac_cmd_common.c",
    "nrf_wifi/fw_if/umac_if/src/common/fmac_api_common.c",
    "nrf_wifi/fw_if/umac_if/src/common/fmac_util.c",
    "nrf_wifi/fw_if/umac_if/src/system/rx.c",
    "nrf_wifi/fw_if/umac_if/src/system/tx.c",
    "nrf_wifi/fw_if/umac_if/src/system/fmac_peer.c",
    "nrf_wifi/fw_if/umac_if/src/system/fmac_vif.c",
    "nrf_wifi/fw_if/umac_if/src/system/fmac_api.c",
    "nrf_wifi/fw_if/umac_if/src/system/fmac_cmd.c",
    "nrf_wifi/fw_if/umac_if/src/system/fmac_event.c",
    "nrf_wifi/hw_if/hal/src/system/hal_api.c",
];

/// Minimal STA-only WPA2-PSK/CCMP subset (verified by compile + nm closure).
/// Everything else (AP, P2P, WPS, EAP, WEP, TKIP, SAE, FT, sockets, files,
/// config parsing) stays compiled out via the absence of its CONFIG_* define.
const HOSTAP_SOURCES: &[&str] = &[
    "src/rsn_supp/wpa.c",
    "src/rsn_supp/wpa_ie.c",
    "src/rsn_supp/pmksa_cache.c",
    "src/common/wpa_common.c",
    "src/common/ieee802_11_common.c",
    "src/utils/common.c",
    // Referenced by ieee802_11_common.c paths unreachable for WPA2-PSK, but
    // needed to satisfy the nm closure.
    "src/utils/wpabuf.c",
    "src/crypto/sha1.c",
    "src/crypto/sha1-internal.c",
    "src/crypto/sha1-prf.c",
    "src/crypto/sha1-pbkdf2.c",
    "src/crypto/sha256.c",
    "src/crypto/sha256-internal.c",
    "src/crypto/sha256-prf.c",
    "src/crypto/aes-internal.c",
    "src/crypto/aes-internal-dec.c",
    "src/crypto/aes-internal-enc.c",
    "src/crypto/aes-unwrap.c",
    "src/crypto/aes-omac1.c",
];

/// hostap feature defines. CONFIG_FIPS drops the hmac_md5 EAPOL-MIC legacy
/// path (its only other effect in this subset is RC4 code already dead under
/// CONFIG_NO_RC4). Never define CONFIG_NO_WPA, IEEE8021X_EAPOL, or __ZEPHYR__.
const HOSTAP_DEFINES: &[&str] = &[
    "CONFIG_NO_STDOUT_DEBUG",
    "CONFIG_NO_WPA_MSG",
    "CONFIG_NO_HOSTAPD_LOGGER",
    "CONFIG_NO_RANDOM_POOL",
    "CONFIG_NO_RC4",
    "CONFIG_NO_TKIP",
    "CONFIG_CRYPTO_INTERNAL",
    "CONFIG_FIPS",
];

/// libc symbols the hostap subset references, interposed to nrf70_os_* like
/// the nrf_wifi build (definitions live in facade.c and supplicant.c).
const HOSTAP_LIBC_INTERPOSERS: &[&str] = &[
    "malloc",
    "calloc",
    "realloc",
    "free",
    "memcpy",
    "memmove",
    "memset",
    "memcmp",
    "strlen",
    "strcmp",
    "strncmp",
    "strchr",
    "strrchr",
    "strstr",
    "strdup",
    "atoi",
    "strtol",
    "printf",
    "snprintf",
    "vsnprintf",
    "qsort",
    "abort",
];

/// Freestanding shims for the libc headers hostap's includes.h pulls in.
/// arm-none-eabi clang has no C library headers; every declaration below is
/// spelled with the libc name and lands on the nrf70_os_* interposer via -D.
const HOSTAP_SHIM_HEADERS: &[(&str, &str)] = &[
    (
        "string.h",
        "#pragma once\n#include <stddef.h>\nvoid *memcpy(void *, const void *, size_t);\nvoid *memmove(void *, const void *, size_t);\nvoid *memset(void *, int, size_t);\nint memcmp(const void *, const void *, size_t);\nsize_t strlen(const char *);\nint strcmp(const char *, const char *);\nint strncmp(const char *, const char *, size_t);\nchar *strchr(const char *, int);\nchar *strrchr(const char *, int);\nchar *strstr(const char *, const char *);\nchar *strdup(const char *);\n",
    ),
    (
        "stdlib.h",
        "#pragma once\n#include <stddef.h>\nvoid *malloc(size_t);\nvoid *calloc(size_t, size_t);\nvoid *realloc(void *, size_t);\nvoid free(void *);\nvoid abort(void);\nint atoi(const char *);\nlong strtol(const char *, char **, int);\nvoid qsort(void *, size_t, size_t, int (*)(const void *, const void *));\n",
    ),
    (
        "stdio.h",
        "#pragma once\n#include <stddef.h>\n#include <stdarg.h>\ntypedef struct nrf70_shim_file FILE; /* declared-only: no stdio paths are compiled in */\nint printf(const char *, ...);\nint snprintf(char *, size_t, const char *, ...);\nint vsnprintf(char *, size_t, const char *, va_list);\n",
    ),
    (
        "errno.h",
        "#pragma once\nextern int nrf70_supp_errno;\n#define errno nrf70_supp_errno\n#define EINVAL 22\n#define ENOMEM 12\n#define ERANGE 34\n",
    ),
    (
        "ctype.h",
        "#pragma once\nstatic inline int isdigit(int c) { return c >= '0' && c <= '9'; }\nstatic inline int isupper(int c) { return c >= 'A' && c <= 'Z'; }\nstatic inline int islower(int c) { return c >= 'a' && c <= 'z'; }\nstatic inline int isalpha(int c) { return isupper(c) || islower(c); }\nstatic inline int isalnum(int c) { return isalpha(c) || isdigit(c); }\nstatic inline int isxdigit(int c) { return isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }\nstatic inline int isspace(int c) { return c == ' ' || (c >= '\\t' && c <= '\\r'); }\nstatic inline int isprint(int c) { return c >= 0x20 && c < 0x7f; }\nstatic inline int iscntrl(int c) { return (c >= 0 && c < 0x20) || c == 0x7f; }\nstatic inline int tolower(int c) { return isupper(c) ? c + 32 : c; }\nstatic inline int toupper(int c) { return islower(c) ? c - 32 : c; }\n",
    ),
    ("signal.h", "#pragma once\n"),
    ("unistd.h", "#pragma once\n"),
    (
        "sys/types.h",
        "#pragma once\n#include <stddef.h>\ntypedef long ssize_t;\n",
    ),
    ("sys/socket.h", "#pragma once\n"),
    ("sys/uio.h", "#pragma once\n"),
    ("sys/time.h", "#pragma once\n"),
    ("netinet/in.h", "#pragma once\n"),
    ("arpa/inet.h", "#pragma once\n"),
];

/// libc symbols the nrf_wifi sources reference, interposed to nrf70_os_* (the
/// definitions live in facade.c). These are `-D` renames for the cc build only;
/// bindgen must never see them, or the facade header's own declarations would
/// be rewritten too.
const NRF_WIFI_LIBC_INTERPOSERS: &[&str] = &[
    "malloc", "calloc", "free", "memcpy", "memset", "memcmp", "strlen", "strcmp", "printf",
    "snprintf",
];

const INCLUDES: &[&str] = &[
    "nrf70_bm_lib/include",
    "nrf_wifi",
    "nrf_wifi/utils/inc",
    "nrf_wifi/os_if/inc",
    "nrf_wifi/bus_if/bus/qspi/inc",
    "nrf_wifi/bus_if/bal/inc",
    "nrf_wifi/fw_if/umac_if/inc",
    "nrf_wifi/fw_if/umac_if/inc/fw",
    "nrf_wifi/hw_if/hal/inc",
];

const ZERO_DEFINES: &[&str] = &[
    "CONFIG_NRF70_PCB_LOSS_2G",
    "CONFIG_NRF70_PCB_LOSS_5G_BAND1",
    "CONFIG_NRF70_PCB_LOSS_5G_BAND2",
    "CONFIG_NRF70_PCB_LOSS_5G_BAND3",
    "CONFIG_NRF70_ANT_GAIN_2G",
    "CONFIG_NRF70_ANT_GAIN_5G_BAND1",
    "CONFIG_NRF70_ANT_GAIN_5G_BAND2",
    "CONFIG_NRF70_ANT_GAIN_5G_BAND3",
    "CONFIG_NRF70_BAND_2G_LOWER_EDGE_BACKOFF_DSSS",
    "CONFIG_NRF70_BAND_2G_LOWER_EDGE_BACKOFF_HT",
    "CONFIG_NRF70_BAND_2G_LOWER_EDGE_BACKOFF_HE",
    "CONFIG_NRF70_BAND_2G_UPPER_EDGE_BACKOFF_DSSS",
    "CONFIG_NRF70_BAND_2G_UPPER_EDGE_BACKOFF_HT",
    "CONFIG_NRF70_BAND_2G_UPPER_EDGE_BACKOFF_HE",
    "CONFIG_NRF70_BAND_UNII_1_LOWER_EDGE_BACKOFF_HT",
    "CONFIG_NRF70_BAND_UNII_1_LOWER_EDGE_BACKOFF_HE",
    "CONFIG_NRF70_BAND_UNII_1_UPPER_EDGE_BACKOFF_HT",
    "CONFIG_NRF70_BAND_UNII_1_UPPER_EDGE_BACKOFF_HE",
    "CONFIG_NRF70_BAND_UNII_2A_LOWER_EDGE_BACKOFF_HT",
    "CONFIG_NRF70_BAND_UNII_2A_LOWER_EDGE_BACKOFF_HE",
    "CONFIG_NRF70_BAND_UNII_2A_UPPER_EDGE_BACKOFF_HT",
    "CONFIG_NRF70_BAND_UNII_2A_UPPER_EDGE_BACKOFF_HE",
    "CONFIG_NRF70_BAND_UNII_2C_LOWER_EDGE_BACKOFF_HT",
    "CONFIG_NRF70_BAND_UNII_2C_LOWER_EDGE_BACKOFF_HE",
    "CONFIG_NRF70_BAND_UNII_2C_UPPER_EDGE_BACKOFF_HT",
    "CONFIG_NRF70_BAND_UNII_2C_UPPER_EDGE_BACKOFF_HE",
    "CONFIG_NRF70_BAND_UNII_3_LOWER_EDGE_BACKOFF_HT",
    "CONFIG_NRF70_BAND_UNII_3_LOWER_EDGE_BACKOFF_HE",
    "CONFIG_NRF70_BAND_UNII_3_UPPER_EDGE_BACKOFF_HT",
    "CONFIG_NRF70_BAND_UNII_3_UPPER_EDGE_BACKOFF_HE",
    "CONFIG_NRF70_BAND_UNII_4_LOWER_EDGE_BACKOFF_HT",
    "CONFIG_NRF70_BAND_UNII_4_LOWER_EDGE_BACKOFF_HE",
    "CONFIG_NRF70_BAND_UNII_4_UPPER_EDGE_BACKOFF_HT",
    "CONFIG_NRF70_BAND_UNII_4_UPPER_EDGE_BACKOFF_HE",
];

/// Flags bindgen also needs to agree with the cc build on type layout.
const ARM_TARGET: &[&str] = &[
    "--target=arm-none-eabi",
    "-mcpu=cortex-m33",
    "-mthumb",
    "-mfloat-abi=hard",
    "-mfpu=fpv5-sp-d16",
];
/// Codegen flags that apply to the C compilations only.
const ARM_CODEGEN: &[&str] = &[
    "-ffunction-sections",
    "-fdata-sections",
    "-fno-strict-aliasing",
    "-fno-builtin",
    "-ffreestanding",
];

/// In-tree edits to pinned vendor sources, applied to a copy in OUT_DIR. Each
/// `edits` pattern must occur exactly once at the point it is applied; they
/// are applied in order (load-bearing for hal_api_common.c).
struct Patch {
    source: &'static str,
    out_name: &'static str,
    edits: &'static [(&'static str, &'static str)],
}

const PATCHES: &[Patch] = &[
    Patch {
        // Validate RX metadata before reads or buffer mutations, and recycle
        // descriptors even when conversion drops a malformed packet.
        source: "nrf_wifi/fw_if/umac_if/src/system/rx.c",
        out_name: "rx_checked.c",
        edits: &[
            (
                r#"static void nrf_wifi_convert_amsdu_to_eth(void *nwb)"#,
                r#"static enum nrf_wifi_status nrf_wifi_convert_amsdu_to_eth(void *nwb)"#,
            ),
            (
                r#"	amsdu_hdr_len = sizeof(struct nrf_wifi_fmac_amsdu_hdr);
"#,
                r#"	amsdu_hdr_len = sizeof(struct nrf_wifi_fmac_amsdu_hdr);
	/* The EtherType helper reads all eight LLC/SNAP bytes. */
	if (nrf_wifi_osal_nbuf_data_size(nwb) < amsdu_hdr_len + 8U) {
		return NRF_WIFI_STATUS_FAIL;
	}
"#,
            ),
            (
                r#"	nrf_wifi_osal_nbuf_data_pull(nwb,
					 (amsdu_hdr_len +
					  nrf_wifi_get_skip_header_bytes(eth_type)));"#,
                r#"	if (!nrf_wifi_osal_nbuf_data_pull(nwb, amsdu_hdr_len +
					 nrf_wifi_get_skip_header_bytes(eth_type))) {
		return NRF_WIFI_STATUS_FAIL;
	}"#,
            ),
            (
                r#"	nrf_wifi_osal_mem_cpy(ehdr->src,
				  amsdu_hdr.src,"#,
                r#"	if (!ehdr) {
		return NRF_WIFI_STATUS_FAIL;
	}

	nrf_wifi_osal_mem_cpy(ehdr->src,
				  amsdu_hdr.src,"#,
            ),
            (
                r#"		ehdr->proto = len;
	}
}

static void nrf_wifi_convert_to_eth"#,
                r#"		ehdr->proto = len;
	}
	return NRF_WIFI_STATUS_SUCCESS;
}

static enum nrf_wifi_status nrf_wifi_convert_to_eth"#,
            ),
            (
                r#"	switch (hdr->fc & (NRF_WIFI_FCTL_TODS | NRF_WIFI_FCTL_FROMDS)) {"#,
                r#"	if (!ehdr) {
		return NRF_WIFI_STATUS_FAIL;
	}

	switch (hdr->fc & (NRF_WIFI_FCTL_TODS | NRF_WIFI_FCTL_FROMDS)) {"#,
            ),
            (
                r#"		ehdr->proto = len;
	}
}
#endif /* NRF70_STA_MODE */"#,
                r#"		ehdr->proto = len;
	}
	return NRF_WIFI_STATUS_SUCCESS;
}
#endif /* NRF70_STA_MODE */"#,
            ),
            (
                r#"	unsigned int pkt_len = 0;"#,
                r#"	unsigned int pkt_len = 0;
	bool drop;
	enum nrf_wifi_status result = NRF_WIFI_STATUS_SUCCESS;"#,
            ),
            (
                r#"	vif_ctx = sys_dev_ctx->vif_ctx[config->wdev_id];"#,
                r#"	if (config->umac_head.len < sizeof(*config) ||
	    config->rx_pkt_cnt > (config->umac_head.len - sizeof(*config)) /
				 sizeof(config->rx_buff_info[0])) {
		return NRF_WIFI_STATUS_FAIL;
	}
	if (config->wdev_id < MAX_NUM_VIFS) {
		vif_ctx = sys_dev_ctx->vif_ctx[config->wdev_id];
	}"#,
            ),
            (
                r#"	if (config->rx_pkt_type != NRF_WIFI_RAW_RX_PKT) {"#,
                r#"	if (vif_ctx && config->rx_pkt_type != NRF_WIFI_RAW_RX_PKT) {"#,
            ),
            (
                r#"		nwb_data = (void *)nrf_wifi_sys_hal_buf_unmap_rx(fmac_dev_ctx->hal_dev_ctx,
								 pkt_len,"#,
                r#"		rx_buf_info = &sys_dev_ctx->rx_buf_info[desc_id];
		if (!rx_buf_info->mapped || !rx_buf_info->nwb) {
			result = NRF_WIFI_STATUS_FAIL;
			continue;
		}
		/* Reject before HAL copies from packet RAM into the host allocation. */
		drop = !pkt_len || pkt_len > sys_fpriv->rx_buf_pools[pool_info.pool_id].buf_sz;
		nwb_data = (void *)nrf_wifi_sys_hal_buf_unmap_rx(fmac_dev_ctx->hal_dev_ctx,
								 drop ? 0 : pkt_len,"#,
            ),
            (
                r#"		rx_buf_info = &sys_dev_ctx->rx_buf_info[desc_id];
		nwb = (void *)rx_buf_info->nwb;

		/**
		 * For nRF71 the RX_BUF_HEADROOM does not seem to be needed.
		 * Remove the same. What parameters does RX_BUF_HEADROOM have??
		 */
		nrf_wifi_osal_nbuf_data_put(nwb,
						pkt_len + RX_BUF_HEADROOM);
		nrf_wifi_osal_nbuf_data_pull(nwb,
						 RX_BUF_HEADROOM);
		nwb_data = nrf_wifi_osal_nbuf_data_get(nwb);
		rx_buf_info->nwb = 0;
		rx_buf_info->mapped = false;"#,
                r#"		nwb = (void *)rx_buf_info->nwb;
		rx_buf_info->nwb = 0;
		rx_buf_info->mapped = false;
		if (drop || !vif_ctx ||
		    !nrf_wifi_osal_nbuf_data_put(nwb, pkt_len + RX_BUF_HEADROOM) ||
		    !nrf_wifi_osal_nbuf_data_pull(nwb, RX_BUF_HEADROOM)) {
			goto drop_packet;
		}
		nwb_data = nrf_wifi_osal_nbuf_data_get(nwb);"#,
            ),
            (
                r#"			case PKT_TYPE_MPDU:
				nrf_wifi_osal_mem_cpy(&hdr,
							  nwb_data,
							  sizeof(struct nrf_wifi_fmac_ieee80211_hdr));"#,
                r#"			case PKT_TYPE_MPDU:
				/* Three addresses need 24 bytes; addr_4 only exists for WDS. */
				if (config->mac_header_len < 24 ||
				    config->mac_header_len > pkt_len ||
				    pkt_len - config->mac_header_len < 8) {
					goto drop_packet;
				}
				nrf_wifi_osal_mem_set(&hdr, 0, sizeof(hdr));
				nrf_wifi_osal_mem_cpy(&hdr, nwb_data, 24);
				if ((hdr.fc & (NRF_WIFI_FCTL_TODS | NRF_WIFI_FCTL_FROMDS)) ==
				    (NRF_WIFI_FCTL_TODS | NRF_WIFI_FCTL_FROMDS)) {
					if (config->mac_header_len < sizeof(hdr)) {
						goto drop_packet;
					}
					nrf_wifi_osal_mem_cpy(hdr.addr_4, (char *)nwb_data + 24,
							  sizeof(hdr.addr_4));
				}"#,
            ),
            (
                r#"				nrf_wifi_osal_nbuf_data_pull(nwb,
								 size);

				nrf_wifi_convert_to_eth(nwb,
							&hdr,
							eth_type);"#,
                r#"				if (!nrf_wifi_osal_nbuf_data_pull(nwb, size) ||
				    nrf_wifi_convert_to_eth(nwb, &hdr, eth_type) !=
							NRF_WIFI_STATUS_SUCCESS) {
					goto drop_packet;
				}"#,
            ),
            (
                r#"				nrf_wifi_osal_nbuf_data_pull(nwb,
								 config->mac_header_len);

				nrf_wifi_convert_amsdu_to_eth(nwb);
				break;
			case PKT_TYPE_MSDU:
				nrf_wifi_convert_amsdu_to_eth(nwb);"#,
                r#"				if (config->mac_header_len < 24 ||
				    !nrf_wifi_osal_nbuf_data_pull(nwb, config->mac_header_len)) {
					goto drop_packet;
				}
				/* fall through */
			case PKT_TYPE_MSDU:
				if (nrf_wifi_convert_amsdu_to_eth(nwb) != NRF_WIFI_STATUS_SUCCESS) {
					goto drop_packet;
				}"#,
            ),
            (
                r#"							  (config->rx_buff_info[i].pkt_type));
				status = NRF_WIFI_STATUS_FAIL;
				continue;"#,
                r#"							  (config->rx_buff_info[i].pkt_type));
				goto drop_packet;"#,
            ),
            (
                r#"			status = NRF_WIFI_STATUS_FAIL;
			nrf_wifi_osal_nbuf_free(nwb);
			continue;
		}

		status = nrf_wifi_fmac_rx_cmd_send"#,
                r#"			goto drop_packet;
		}
		goto refill;
drop_packet:
		result = NRF_WIFI_STATUS_FAIL;
		nrf_wifi_osal_nbuf_free(nwb);
refill:
		status = nrf_wifi_fmac_rx_cmd_send"#,
            ),
            (
                r#"						  desc_id);
			status = NRF_WIFI_STATUS_FAIL;
			continue;"#,
                r#"						  desc_id);
			result = NRF_WIFI_STATUS_FAIL;
			continue;"#,
            ),
            (
                r#"			status = NRF_WIFI_STATUS_FAIL;
			continue;
		}
		rx_buf_info = &sys_dev_ctx->rx_buf_info[desc_id];"#,
                r#"			result = NRF_WIFI_STATUS_FAIL;
			continue;
		}
		rx_buf_info = &sys_dev_ctx->rx_buf_info[desc_id];"#,
            ),
            (
                r#"			status = NRF_WIFI_STATUS_FAIL;
			continue;
		}
		nwb = (void *)rx_buf_info->nwb;"#,
                r#"			result = NRF_WIFI_STATUS_FAIL;
			continue;
		}
		nwb = (void *)rx_buf_info->nwb;"#,
            ),
            (
                r#"			nrf_wifi_osal_log_err("%s: nrf_wifi_fmac_rx_cmd_send failed",
						  __func__);
			continue;"#,
                r#"			nrf_wifi_osal_log_err("%s: nrf_wifi_fmac_rx_cmd_send failed",
						  __func__);
			result = NRF_WIFI_STATUS_FAIL;
			continue;"#,
            ),
            (
                r#"#endif /*NRF_WIFI_RX_BUFF_PROG_UMAC */
	return status;
}"#,
                r#"#endif /*NRF_WIFI_RX_BUFF_PROG_UMAC */
	return result == NRF_WIFI_STATUS_FAIL ? result : status;
}"#,
            ),
        ],
    },
    Patch {
        source: "nrf_wifi/fw_if/umac_if/src/system/fmac_api.c",
        out_name: "fmac_api_open_bssid.c",
        edits: &[(
            "\tif (auth_info->ssid.nrf_wifi_ssid_len > 0) {\n\t\tauth_cmd->valid_fields |= NRF_WIFI_CMD_AUTHENTICATE_SSID_VALID;\n\t}\n",
            "\tif (auth_info->ssid.nrf_wifi_ssid_len > 0) {\n\t\tauth_cmd->valid_fields |= NRF_WIFI_CMD_AUTHENTICATE_SSID_VALID;\n\t}\n\n\tif (!nrf_wifi_util_is_arr_zero(auth_info->nrf_wifi_bssid,\n\t\t\t\t       sizeof(auth_info->nrf_wifi_bssid))) {\n\t\tauth_cmd->valid_fields |= NRF_WIFI_CMD_AUTHENTICATE_BSSID_VALID;\n\t}\n",
        )],
    },
    Patch {
        source: "nrf_wifi/hw_if/hal/src/common/hal_api_common.c",
        out_name: "hal_api_common_bounded.c",
        edits: &[
            (
                "unsigned int event_len = 0;\n\n\twhile (1) {",
                "unsigned int event_len = 0;\n\tunsigned int facade_events_processed = 0;\n\n\twhile (facade_events_processed < 1) {",
            ),
            (
                "nrf_wifi_osal_mem_free(event);\n\t\tevent = NULL;\n\t}\n\nout:\n\treturn status;",
                "nrf_wifi_osal_mem_free(event);\n\t\tevent = NULL;\n\t\tfacade_events_processed++;\n\t}\n\tif (facade_events_processed == 1) {\n\t\tnrf_wifi_osal_tasklet_schedule(hal_dev_ctx->event_tasklet);\n\t}\n\nout:\n\treturn status;",
            ),
        ],
    },
    Patch {
        // The RPU acknowledges every coex table write with
        // NRF_WIFI_EVENT_COEX_CONFIG, which the pinned dispatcher rejects as unknown.
        source: "nrf_wifi/fw_if/umac_if/src/system/fmac_event.c",
        out_name: "fmac_event_coex_ack.c",
        edits: &[(
            "#endif /* NRF70_RAW_DATA_RX || NRF70_PROMISC_DATA_RX */\n\tdefault:",
            "#endif /* NRF70_RAW_DATA_RX || NRF70_PROMISC_DATA_RX */\n\tcase NRF_WIFI_EVENT_COEX_CONFIG:\n\t\tstatus = NRF_WIFI_STATUS_SUCCESS;\n\t\tbreak;\n\tdefault:",
        )],
    },
    Patch {
        source: "nrf_wifi/hw_if/hal/src/common/hal_interrupt.c",
        out_name: "hal_interrupt_bounded.c",
        edits: &[
            (
                "unsigned int event_addr = 0;\n\n\twhile (1) {",
                "unsigned int event_addr = 0;\n\tunsigned int facade_events_fetched = 0;\n\n\twhile (facade_events_fetched < 1) {",
            ),
            (
                "\t\tnum_events++;\n\t}\n\nout:",
                // The caller acknowledges HOST_IRQ even if more events remain.
                // Continue in software: waiting for another GPIO edge/level can
                // strand the IFFLAGS response forever after a coalesced IRQ.
                "\t\tnum_events++;\n\t\tfacade_events_fetched++;\n\t}\n\tif (facade_events_fetched == 1) {\n\t\textern void nrf70_facade_notify_host_irq(void);\n\t\tnrf70_facade_notify_host_irq();\n\t}\n\nout:",
            ),
        ],
    },
];

/// Resolves an LLVM binary shipped in the rustc sysroot for the host triple.
fn llvm_tool(name: &str) -> PathBuf {
    let sysroot = Command::new(env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
        .args(["--print", "sysroot"])
        .output()
        .expect("rustc sysroot");
    PathBuf::from(String::from_utf8(sysroot.stdout).unwrap().trim()).join(format!(
        "lib/rustlib/{}/bin/{name}",
        env::var("HOST").unwrap()
    ))
}
/// Resolves a pinned vendor source, checking that it still carries its license
/// notice.
fn vendored(root: &Path, rel: &str, notice: &str) -> PathBuf {
    let p = root.join(rel);
    let source =
        fs::read_to_string(&p).unwrap_or_else(|e| panic!("vendored source {}: {e}", p.display()));
    assert!(
        source.contains(notice),
        "`{notice}` notice absent: {}",
        p.display()
    );
    println!("cargo:rerun-if-changed={}", p.display());
    p
}

fn patch(path: &Path, patch: &Patch, out: &Path) -> PathBuf {
    let mut source = fs::read_to_string(path).unwrap();
    for (i, (from, to)) in patch.edits.iter().enumerate() {
        assert_eq!(
            source.matches(from).count(),
            1,
            "edit {i} for {} no longer applies to the pinned source",
            patch.out_name
        );
        source = source.replacen(from, to, 1);
    }
    let patched = out.join(patch.out_name);
    fs::write(&patched, source).unwrap();
    patched
}

fn hash(path: &Path) -> String {
    format!(
        "{:x}",
        Sha256::digest(fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
    )
}
fn require_revision(path: &Path, expected: &str) {
    let out = Command::new("git")
        .args(["-C", path.to_str().unwrap(), "rev-parse", "HEAD"])
        .output()
        .expect("git is required to verify pinned nRF70 sources");
    let got = String::from_utf8(out.stdout).unwrap();
    assert!(
        out.status.success() && got.trim() == expected,
        "pinned revision mismatch at {}: expected {expected}, got {}",
        path.display(),
        got.trim()
    );
}

/// Fails unless every symbol either archive leaves undefined is defined by
/// the other (facade.c and supplicant.c depend on each other).
fn check_symbol_closure(out: &Path) {
    let nm = llvm_tool("llvm-nm");
    assert!(
        nm.is_file(),
        "llvm-nm is required for the OSAL undefined-symbol inventory"
    );
    let archives = [
        out.join("libnrf70_system.a"),
        out.join("libnrf70_supplicant.a"),
    ];
    let symbols = |kind: &str| -> BTreeSet<String> {
        let mut set = BTreeSet::new();
        for archive in &archives {
            let o = Command::new(&nm)
                .args([kind, "--format=posix", archive.to_str().unwrap()])
                .output()
                .expect("llvm-nm");
            assert!(o.status.success(), "llvm-nm failed");
            set.extend(
                String::from_utf8(o.stdout)
                    .unwrap()
                    .lines()
                    .filter_map(|l| l.split_whitespace().next())
                    .map(str::to_owned),
            );
        }
        set
    };
    let defined = symbols("--defined-only");
    let external: Vec<_> = symbols("--undefined-only")
        .into_iter()
        .filter(|s| {
            !defined.contains(s)
                && !matches!(
                    s.as_str(),
                    "__aeabi_memclr" | "__aeabi_memclr4" | "__aeabi_memcpy" | "__aeabi_memcpy4"
                )
        })
        .collect();
    assert!(
        external.is_empty(),
        "unresolved nRF70 platform/OSAL symbols: {external:?}"
    );
}
const DEFINES: &[(&str, &str)] = &[
    ("NRF70_STA_MODE", "1"),
    // The op-mode gate in fmac_api_common.c needs exactly one of
    // NRF70_SCAN_ONLY / NRF70_SYSTEM_MODE / NRF70_SYSTEM_WITH_RAW_MODES;
    // this must match the embedded blob's feature flag (default = system).
    ("NRF70_SYSTEM_MODE", "1"),
    ("NRF70_DATA_TX", "1"),
    ("CONFIG_NRF70_BOARD_TYPE_EK", "1"),
    ("CONFIG_NRF70_BM_LOG_LEVEL", "0"),
    ("CONFIG_NRF70_SCAN_SSID_FILT_MAX", "2"),
    ("CONFIG_NRF70_SCAN_CHAN_MAX_MANUAL", "32"),
    ("CONFIG_NRF_WIFI_SCAN_MAX_BSS_CNT", "64"),
    ("CONFIG_NRF70_OTP_MAC_ADDRESS", "1"),
    ("CONFIG_NRF_WIFI_LOW_POWER", "1"),
    ("NRF_WIFI_LOW_POWER", "1"),
    ("CONFIG_NRF_WIFI_BEAMFORMING", "1"),
    // nrf70_bm_lib's Kconfig numbering: 1 = 2.4 GHz, 2 = 5 GHz, 3 = both.
    ("CONFIG_NRF_WIFI_OP_BAND", "3"),
    ("NRF_WIFI_MAX_PS_POLL_FAIL_CNT", "10"),
    // Total RX buffers across all MAX_NUM_OF_RX_QUEUES pools (the HAL
    // sizes its PKTRAM reservation from this); must divide evenly by 3.
    ("NRF70_RX_NUM_BUFS", "6"),
    ("NRF70_RX_MAX_DATA_SIZE", "1600"),
    ("NRF70_MAX_TX_TOKENS", "5"),
    ("NRF70_MAX_TX_PENDING_QLEN", "8"),
    ("NRF70_PATCH_DL_CHUNK_SIZE", "4096"),
    ("NRF70_RPU_PS_IDLE_TIMEOUT_MS", "10"),
    ("NRF_WIFI_DISPLAY_SCAN_BSS_LIMIT", "64"),
    ("NRF_WIFI_RPU_MIN_TIME_TO_ENTER_SLEEP_MS", "1000"),
    ("NRF_WIFI_IFACE_MTU", "1500"),
    ("NRF_WIFI_AP_DEAD_DETECT_TIMEOUT", "300"),
    ("NRF_WIFI_PS_INT_PS", "1"),
    // Run the RPU's coexistence manager (bt_coex_disable = 0) and compile in
    // the sleep-control GPIO setup facade.c does after firmware load. The
    // PTA tables are sent at run time by nrf70_facade_coex_configure.
    ("NRF70_SR_COEX", "1"),
    ("NRF70_BT_SLOT_TIME", "100"),
    ("NRF70_SR_COEX_SLEEP_CTRL_GPIO_CTRL", "1"),
    ("CONFIG_NRF70_REG_DOMAIN", "00"),
    ("WIFI_NRF70_LOG_LEVEL", "1"),
];

fn define_args(firmware: &Path) -> Vec<(String, String)> {
    let zero = ZERO_DEFINES.iter().copied().chain(
        ZERO_DEFINES
            .iter()
            .filter_map(|x| x.strip_prefix("CONFIG_")),
    );
    DEFINES
        .iter()
        .map(|&(k, v)| (k.to_owned(), v.to_owned()))
        .chain([(
            "CONFIG_NRF_WIFI_SYS_FW_BIN".to_owned(),
            firmware.display().to_string(),
        )])
        .chain(
            NRF_WIFI_LIBC_INTERPOSERS
                .iter()
                .map(|x| (x.to_string(), format!("nrf70_os_{x}"))),
        )
        .chain(zero.map(|x| (x.to_owned(), "0".to_owned())))
        .collect()
}

fn main() {
    println!("cargo:rerun-if-changed=include");
    println!("cargo:rerun-if-changed=vendor-manifest.toml");
    println!("cargo:rerun-if-changed=THIRD_PARTY_NOTICES.md");
    println!("cargo:rerun-if-changed=src/facade.c");
    println!("cargo:rerun-if-changed=src/facade_mock.c");
    println!("cargo:rerun-if-changed=src/supplicant.c");
    println!("cargo:rerun-if-changed=src/supplicant.h");
    println!("cargo:rerun-if-changed=vendor");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let mock = env::var_os("CARGO_FEATURE_MOCK").is_some();
    assert!(
        mock || env::var("TARGET").unwrap() == TARGET,
        "real nrf70-sys must be built for {TARGET}; use feature `mock` only for host tests"
    );

    let mut clang_args = vec!["-Iinclude".to_string(), "-fno-short-enums".into()];
    let mut build = cc::Build::new();
    build
        .compiler("clang")
        // The pinned Nordic sources contain numerous benign warnings. Since
        // cc forwards every diagnostic as a Cargo warning (and Cargo replays
        // them on cached builds), keep them from flooding MCU build output.
        .warnings(false)
        .include("include")
        .flag("-std=c11")
        .flag("-fno-short-enums");
    if mock {
        build.file("src/facade_mock.c");
        build.compile("nrf70_system");
    } else {
        let root = PathBuf::from("../../third_party/nrf70-bm").canonicalize().expect("missing pinned third_party/nrf70-bm submodule; run git submodule update --init --recursive");
        require_revision(&root, NRF70_BM_REV);
        require_revision(&root.join("nrf_wifi"), NRF_WIFI_REV);
        require_revision(&root.join("sdk-nrfxlib"), NRFXLIB_REV);
        let clang = Command::new("clang")
            .arg("--version")
            .output()
            .expect("pinned Clang 21 is required");
        let version = String::from_utf8_lossy(&clang.stdout);
        let version = version.lines().next().unwrap_or("unknown");
        assert!(
            version.contains(&format!("{CLANG_MAJOR_VERSION}.")),
            "Clang {CLANG_MAJOR_VERSION} is pinned, found: {version}"
        );
        let fw = root.join("sdk-nrfxlib/nrf_wifi/bin/zephyr/default/nrf70.bin");
        let lic = root.join("sdk-nrfxlib/LICENSE");
        assert_eq!(hash(&fw), BLOB_SHA256, "firmware hash mismatch");
        assert_eq!(
            hash(&lic),
            LICENSE_SHA256,
            "required Nordic license hash mismatch"
        );
        println!("cargo:rerun-if-changed={}", fw.display());
        println!("cargo:rerun-if-changed={}", lic.display());
        let llvm_ar = llvm_tool("llvm-ar");
        if llvm_ar.is_file() {
            build.archiver(&llvm_ar);
        }
        build.flags(ARM_TARGET).flags(ARM_CODEGEN);
        clang_args.extend(ARM_TARGET.iter().map(|x| x.to_string()));
        for i in INCLUDES {
            let p = root.join(i);
            build.include(&p);
            clang_args.push(format!("-I{}", p.display()));
        }
        for (k, v) in define_args(&fw) {
            build.define(&k, v.as_str());
            if !NRF_WIFI_LIBC_INTERPOSERS.contains(&k.as_str()) {
                clang_args.push(format!("-D{k}={v}"));
            }
        }
        build.file("src/facade.c");
        let coex = PathBuf::from("vendor/zephyr_nrf_wifi");
        assert_eq!(
            hash(&coex.join("coex_struct.h")),
            COEX_STRUCT_SHA256,
            "vendored coex_struct.h drifted from upstream"
        );
        for name in ["coex_struct.h", "coex.h", "coex.c"] {
            vendored(&coex, name, "SPDX-License-Identifier: Apache-2.0");
        }
        build.include(&coex);
        build.file(coex.join("coex.c"));
        for s in SOURCES {
            let p = vendored(&root, s, "SPDX-License-Identifier: BSD-3-Clause");
            match PATCHES.iter().find(|x| x.source == *s) {
                Some(x) => build.file(patch(&p, x, &out)),
                None => build.file(p),
            };
        }

        // Second archive: the hostap WPA2-PSK subset plus supplicant.c, which
        // needs the same defines and shim headers. facade.c never sees hostap
        // headers.
        let hostap = PathBuf::from("../../third_party/hostap").canonicalize().expect(
            "missing pinned third_party/hostap submodule; run git submodule update --init --recursive",
        );
        require_revision(&hostap, HOSTAP_REV);
        let shim = out.join("hostap_shim");
        for (name, contents) in HOSTAP_SHIM_HEADERS {
            let p = shim.join(name);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, contents).unwrap();
        }
        let mut supp = cc::Build::new();
        supp.compiler("clang")
            // hostap's disabled-feature stubs are intentionally warning-heavy.
            .warnings(false)
            .flag("-std=c11")
            .flag("-fno-short-enums")
            .flags(ARM_TARGET)
            .flags(ARM_CODEGEN)
            .include(&shim)
            .include(hostap.join("src"))
            .include(hostap.join("src/utils"));
        if llvm_ar.is_file() {
            supp.archiver(&llvm_ar);
        }
        for d in HOSTAP_DEFINES {
            supp.define(d, None);
        }
        for s in HOSTAP_LIBC_INTERPOSERS {
            supp.define(s, Some(format!("nrf70_os_{s}").as_str()));
        }
        // common.h's fallback byte-order block needs these on a freestanding
        // target; Cortex-M33 is little-endian.
        supp.define("__BYTE_ORDER", Some("1234"))
            .define("__LITTLE_ENDIAN", Some("1234"))
            .define("__BIG_ENDIAN", Some("4321"))
            .define("bswap_16", Some("__builtin_bswap16"))
            .define("bswap_32", Some("__builtin_bswap32"))
            .define("bswap_64", Some("__builtin_bswap64"));
        for s in HOSTAP_SOURCES {
            supp.file(vendored(
                &hostap,
                s,
                "distributed under the terms of the BSD license",
            ));
        }
        supp.file("src/supplicant.c");

        build.compile("nrf70_system");
        supp.compile("nrf70_supplicant");
        check_symbol_closure(&out);
    }
    let bindings = bindgen::Builder::default()
        .header("include/nrf70_facade.h")
        .allowlist_type("nrf70_facade_.*")
        .allowlist_function("nrf70_facade_.*")
        .allowlist_var("NRF70_FACADE_.*")
        .use_core()
        .ctypes_prefix("core::ffi")
        .layout_tests(false)
        .derive_default(true)
        .clang_args(&clang_args)
        .generate()
        .expect("failed to generate private facade bindings");
    bindings.write_to_file(out.join("bindings.rs")).unwrap();
}
