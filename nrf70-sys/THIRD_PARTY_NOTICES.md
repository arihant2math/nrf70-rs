# Third-party notices

The selected `nrf70-bm` and `nrf_wifi` source files identify themselves as
BSD-3-Clause. Copyright remains with Nordic Semiconductor ASA and the respective
contributors. Preserve those file headers in source distributions.

The WPA2-Personal supplicant subset is built from the `hostap`
(wpa_supplicant/hostapd) project, vendored at `vendor/hostap`. hostap was
historically dual-licensed BSD/GPLv2; we use it under the BSD option. The
project's `COPYING` file states: "This software was previously distributed
under BSD/GPL v2 dual license terms that allowed either of those license
alternatives to be selected. As of February 11, 2012, the project has chosen to
use only the BSD license option for future distribution." The controlling
BSD-3-Clause text is in `vendor/hostap/README`. Copyright (c) 2002-2022,
Jouni Malinen <j@w1.fi> and contributors. The build verifies that every
compiled hostap source file carries the per-file BSD license notice. Preserve
those file headers in source distributions.

The nRF70 coexistence (PTA) tables in `vendor/zephyr_nrf_wifi/` come from the
Zephyr Project's `drivers/wifi/nrf_wifi` driver and are **Apache-2.0**,
Copyright (c) 2024-2026 Nordic Semiconductor ASA. `coex_struct.h` is verbatim;
`coex.c` and `coex.h` are modified, and each file's header states the changes
as Apache-2.0 §4(b) requires. Preserve those headers in source distributions.

The system-mode firmware at
`vendor/nrf70-bm/sdk-nrfxlib/nrf_wifi/bin/zephyr/default/nrf70.bin` is
binary software under Nordic's **LicenseRef-Nordic-5-Clause**, not BSD software.
The controlling license text is checked in at
`vendor/nrf70-bm/sdk-nrfxlib/LICENSE`. In particular, use is restricted to
Nordic integrated circuits and the binary must not be reverse engineered,
modified, or disassembled. Distributions containing firmware must include that
license.

Exact revisions and hashes are in `vendor-manifest.toml`. `vendor.sh`
regenerates `vendor/nrf70-bm` and `vendor/hostap` from those revisions.
