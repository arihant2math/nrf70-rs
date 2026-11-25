# nrf70-rs

`no_std` Rust driver for the nRF7002 in system (FMAC) mode, with an
embassy-net data plane and a WPA2-Personal supplicant.

- `nrf70`: safe async driver. See [`nrf70/README.md`](nrf70/README.md).
- `nrf70-sys`: binding to Nordic's `nrf_wifi` and a hostap subset, vendored
  under `nrf70-sys/vendor`. The bundled firmware blob is under Nordic's
  5-Clause license; see
  [`nrf70-sys/THIRD_PARTY_NOTICES.md`](nrf70-sys/THIRD_PARTY_NOTICES.md).

Building for `thumbv8m.main-none-eabihf` needs `clang` on `PATH` and
libclang for bindgen (set `LIBCLANG_PATH` if it is not found). Host tests:

```sh
cargo test --workspace --target "$(rustc -vV | awk '/^host:/ {print $2}')" --features nrf70/mock
```

`nrf70` is licensed under MIT or Apache-2.0, at your option.
