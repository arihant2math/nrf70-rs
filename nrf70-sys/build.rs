use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const TARGET: &str = "thumbv8m.main-none-eabihf";
const CLANG_VERSION: &str = "21.1.8";
const BLOB_SHA256: &str = "36b84d10037a9609a2a0fe86a0ef5b53fcd5fc2e88621c6d8f0f711b76775b1e";
const LICENSE_SHA256: &str = "47d92141c69e74a0166c319a41e5005ce2b87f0498e5dbd5a0c5a34f9ef63954";
const NRF70_BM_REV: &str = "185ec021afb61dc2d42b4f65800c3aa3d27c88d6";
const NRF_WIFI_REV: &str = "0aaa9aa812877cb6bc020df8260d0607a3f0ec1a";
const NRFXLIB_REV: &str = "f1591c62b301c2dc8d91308d43903de563f64d81";
const HOSTAP_REV: &str = "d467a115b8fc20b8b7120937cb1d445dacebc6a1";

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
    /* wpabuf helpers are referenced by ieee802_11_common.c utility paths that
     * are unreachable for WPA2-PSK but must still satisfy the nm closure. */
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

/// The five flags bindgen's libclang invocation needs to agree with the cc
/// build about the target's type layout.
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

/// In-tree edits to pinned vendor sources. Each is applied to a copy written
/// into OUT_DIR; `edits` are `replacen(.., 1)` in order (order is load-bearing
/// for hal_api_common.c), and `marker` must survive or the pin has drifted.
struct Patch {
    source: &'static str,
    out_name: &'static str,
    edits: &'static [(&'static str, &'static str)],
    marker: &'static str,
    panic_msg: &'static str,
}

const PATCHES: &[Patch] = &[
    Patch {
        source: "nrf_wifi/fw_if/umac_if/src/system/fmac_api.c",
        out_name: "fmac_api_open_bssid.c",
        edits: &[(
            "\tif (auth_info->ssid.nrf_wifi_ssid_len > 0) {\n\t\tauth_cmd->valid_fields |= NRF_WIFI_CMD_AUTHENTICATE_SSID_VALID;\n\t}\n",
            "\tif (auth_info->ssid.nrf_wifi_ssid_len > 0) {\n\t\tauth_cmd->valid_fields |= NRF_WIFI_CMD_AUTHENTICATE_SSID_VALID;\n\t}\n\n\tif (!nrf_wifi_util_is_arr_zero(auth_info->nrf_wifi_bssid,\n\t\t\t\t       sizeof(auth_info->nrf_wifi_bssid))) {\n\t\tauth_cmd->valid_fields |= NRF_WIFI_CMD_AUTHENTICATE_BSSID_VALID;\n\t}\n",
        )],
        marker: "auth_cmd->valid_fields |= NRF_WIFI_CMD_AUTHENTICATE_BSSID_VALID",
        panic_msg: "pinned open-auth BSSID patch no longer applies",
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
                "nrf_wifi_osal_mem_free(event);\n\t\tevent = NULL;\n\t}\n\nout:",
                "nrf_wifi_osal_mem_free(event);\n\t\tevent = NULL;\n\t\tfacade_events_processed++;\n\t}\n\tif (facade_events_processed == 1) {\n\t\tnrf_wifi_osal_tasklet_schedule(hal_dev_ctx->event_tasklet);\n\t}\n\nout:",
            ),
        ],
        marker: "facade_events_processed",
        panic_msg: "pinned event-budget patch no longer applies",
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
                "\t\tnum_events++;\n\t\tfacade_events_fetched++;\n\t}\n\nout:",
            ),
        ],
        marker: "facade_events_fetched",
        panic_msg: "pinned IRQ-budget patch no longer applies",
    },
];

fn apply_arm_flags(build: &mut cc::Build) {
    for flag in ARM_TARGET.iter().chain(ARM_CODEGEN) {
        build.flag(flag);
    }
}
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
/// Resolves one pinned vendor source, checking it exists and still carries its
/// license notice, and registers it for rebuild tracking.
fn vendored(root: &Path, rel: &str, notice: &str, absent_msg: &str, notice_msg: &str) -> PathBuf {
    let p = root.join(rel);
    if !p.is_file() {
        panic!("{absent_msg}: {}", p.display())
    }
    if !fs::read_to_string(&p).unwrap_or_default().contains(notice) {
        panic!("{notice_msg}: {}", p.display())
    }
    println!("cargo:rerun-if-changed={}", p.display());
    p
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
    if !out.status.success() || got.trim() != expected {
        panic!(
            "pinned revision mismatch at {}: expected {expected}, got {}",
            path.display(),
            got.trim()
        );
    }
}
fn define_args(firmware: &Path) -> Vec<(String, String)> {
    let mut d = vec![
        ("NRF70_STA_MODE".into(), "1".into()),
        // The op-mode gate in fmac_api_common.c needs exactly one of
        // NRF70_SCAN_ONLY / NRF70_SYSTEM_MODE / NRF70_SYSTEM_WITH_RAW_MODES;
        // this must match the embedded blob's feature flag (default = system).
        ("NRF70_SYSTEM_MODE".into(), "1".into()),
        ("NRF70_DATA_TX".into(), "1".into()),
        ("CONFIG_NRF70_BOARD_TYPE_EK".into(), "1".into()),
        ("CONFIG_NRF70_BM_LOG_LEVEL".into(), "0".into()),
        ("CONFIG_NRF70_SCAN_SSID_FILT_MAX".into(), "2".into()),
        ("CONFIG_NRF70_SCAN_CHAN_MAX_MANUAL".into(), "32".into()),
        ("CONFIG_NRF_WIFI_SCAN_MAX_BSS_CNT".into(), "64".into()),
        ("CONFIG_NRF70_OTP_MAC_ADDRESS".into(), "1".into()),
        ("CONFIG_NRF_WIFI_LOW_POWER".into(), "1".into()),
        ("NRF_WIFI_LOW_POWER".into(), "1".into()),
        ("CONFIG_NRF_WIFI_BEAMFORMING".into(), "1".into()),
        ("CONFIG_NRF_WIFI_OP_BAND".into(), "2".into()),
        ("NRF_WIFI_MAX_PS_POLL_FAIL_CNT".into(), "10".into()),
        // Total RX buffers across all MAX_NUM_OF_RX_QUEUES pools (the HAL
        // sizes its PKTRAM reservation from this); must divide evenly by 3.
        ("NRF70_RX_NUM_BUFS".into(), "6".into()),
        ("NRF70_RX_MAX_DATA_SIZE".into(), "1600".into()),
        ("NRF70_MAX_TX_TOKENS".into(), "5".into()),
        ("NRF70_MAX_TX_PENDING_QLEN".into(), "8".into()),
        ("NRF70_PATCH_DL_CHUNK_SIZE".into(), "4096".into()),
        ("NRF70_RPU_PS_IDLE_TIMEOUT_MS".into(), "10".into()),
        ("NRF_WIFI_DISPLAY_SCAN_BSS_LIMIT".into(), "64".into()),
        (
            "NRF_WIFI_RPU_MIN_TIME_TO_ENTER_SLEEP_MS".into(),
            "1000".into(),
        ),
        ("NRF_WIFI_IFACE_MTU".into(), "1500".into()),
        ("NRF_WIFI_AP_DEAD_DETECT_TIMEOUT".into(), "300".into()),
        ("NRF_WIFI_PS_INT_PS".into(), "1".into()),
        ("CONFIG_NRF70_REG_DOMAIN".into(), "00".into()),
        ("WIFI_NRF70_LOG_LEVEL".into(), "1".into()),
        (
            "CONFIG_NRF_WIFI_SYS_FW_BIN".into(),
            firmware.display().to_string(),
        ),
    ];
    d.extend(
        NRF_WIFI_LIBC_INTERPOSERS
            .iter()
            .map(|x| (x.to_string(), format!("nrf70_os_{x}"))),
    );
    d.extend(ZERO_DEFINES.iter().map(|x| (x.to_string(), "0".into())));
    d.extend(
        ZERO_DEFINES
            .iter()
            .filter_map(|x| x.strip_prefix("CONFIG_"))
            .map(|x| (x.to_string(), "0".into())),
    );
    d
}

fn main() {
    println!("cargo:rerun-if-changed=include");
    println!("cargo:rerun-if-changed=vendor-manifest.toml");
    println!("cargo:rerun-if-changed=THIRD_PARTY_NOTICES.md");
    println!("cargo:rerun-if-changed=src/facade.c");
    println!("cargo:rerun-if-changed=src/facade_mock.c");
    println!("cargo:rerun-if-changed=src/supplicant.c");
    println!("cargo:rerun-if-changed=src/supplicant.h");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let mock = env::var_os("CARGO_FEATURE_MOCK").is_some();
    let target = env::var("TARGET").unwrap();
    if !mock && target != TARGET {
        panic!("real nrf70-sys must be built for {TARGET}; use feature `mock` only for host tests");
    }

    let mut clang_args = vec!["-Iinclude".to_string(), "-fno-short-enums".into()];
    let mut build = cc::Build::new();
    let mut supplicant_build: Option<cc::Build> = None;
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
        if !version.lines().next().unwrap_or("").contains(CLANG_VERSION) {
            panic!(
                "Clang {CLANG_VERSION} is pinned, found: {}",
                version.lines().next().unwrap_or("unknown")
            );
        }
        let fw = root.join("sdk-nrfxlib/nrf_wifi/bin/zephyr/default/nrf70.bin");
        let lic = root.join("sdk-nrfxlib/LICENSE");
        if hash(&fw) != BLOB_SHA256 {
            panic!("scan firmware hash mismatch");
        }
        if hash(&lic) != LICENSE_SHA256 {
            panic!("required Nordic license hash mismatch");
        }
        println!("cargo:rerun-if-changed={}", fw.display());
        println!("cargo:rerun-if-changed={}", lic.display());
        let llvm_ar = llvm_tool("llvm-ar");
        if llvm_ar.is_file() {
            build.archiver(&llvm_ar);
        }
        apply_arm_flags(&mut build);
        clang_args.extend(ARM_TARGET.iter().map(|x| x.to_string()));
        for i in INCLUDES {
            let p = root.join(i);
            build.include(&p);
            clang_args.push(format!("-I{}", p.display()));
        }
        let defs = define_args(&fw);
        for (k, v) in &defs {
            build.define(k, v.as_str());
            if !NRF_WIFI_LIBC_INTERPOSERS.contains(&k.as_str()) {
                clang_args.push(format!("-D{k}={v}"));
            }
        }
        build.file("src/facade.c");
        for s in SOURCES {
            let p = vendored(
                &root,
                s,
                "SPDX-License-Identifier: BSD-3-Clause",
                "pinned source absent",
                "required BSD-3-Clause notice absent",
            );
            if let Some(patch) = PATCHES.iter().find(|x| x.source == *s) {
                let mut source = fs::read_to_string(&p).unwrap();
                for (from, to) in patch.edits {
                    source = source.replacen(from, to, 1);
                }
                if !source.contains(patch.marker) {
                    panic!("{}", patch.panic_msg)
                }
                let patched = out.join(patch.out_name);
                fs::write(&patched, source).unwrap();
                build.file(patched);
            } else {
                build.file(p);
            }
        }

        /* Second archive: the pinned hostap WPA2-PSK subset plus supplicant.c
         * (which needs the same defines and shim headers). facade.c stays in
         * the nrf70_system archive and never sees hostap headers. */
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
            .flag("-fno-short-enums");
        apply_arm_flags(&mut supp);
        supp.include(&shim)
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
        /* common.h's fallback byte-order block needs these on a freestanding
         * target; Cortex-M33 is little-endian. */
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
                "pinned hostap source absent",
                "required BSD license notice absent",
            ));
        }
        supp.file("src/supplicant.c");
        supplicant_build = Some(supp);
    }
    build.compile("nrf70_system");
    if let Some(supp) = supplicant_build.as_mut() {
        supp.compile("nrf70_supplicant");
    }
    if !mock {
        let nm = llvm_tool("llvm-nm");
        if !nm.is_file() {
            panic!("llvm-nm is required for the OSAL undefined-symbol inventory")
        }
        /* A symbol undefined in one archive may be defined in the other
         * (facade.c <-> supplicant.c are mutually dependent); treat the two
         * archives as one link unit for the closure check. */
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
                if !o.status.success() {
                    panic!("llvm-nm failed")
                };
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
        let undefined = symbols("--undefined-only");
        let defined = symbols("--defined-only");
        let external: Vec<_> = undefined
            .difference(&defined)
            .filter(|s| {
                !matches!(
                    s.as_str(),
                    "__aeabi_memclr" | "__aeabi_memclr4" | "__aeabi_memcpy" | "__aeabi_memcpy4"
                )
            })
            .collect();
        if !external.is_empty() {
            panic!("unresolved nRF70 platform/OSAL symbols: {external:?}")
        }
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
