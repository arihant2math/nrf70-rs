# nrf70

Safe, `no_std`, system-mode nRF7002 driver: Phase 2 data plane plus the
Phase 3 WPA supplicant connect flow.

The crate owns a synchronous `Bus` implementation through a static `Platform`.
All Nordic C entry points, FMAC callbacks, blocking SPI, tasklets, timers, and
the C-side supplicant (a vendored STA-only hostap subset behind the same
facade) run from `Runner::run` on a normal thread-mode Embassy executor. The
GPIO ISR only calls `HostIrq::on_interrupt()`.

The data plane uses `embassy-net-driver-channel` with 1514-byte Ethernet frames
(1500-byte IP MTU, no FCS). C nbufs and Embassy buffers are deliberately copied:
TX is copied into a C-owned nbuf before the Embassy slot is released, and RX is
copied from a bounded C queue before that queue slot is released. Queue depths
are application-selected and should remain small and measured.

```rust,ignore
static RESOURCES: StaticCell<nrf70::Resources> = StaticCell::new();
static PLATFORM: StaticCell<nrf70::Platform<MyNrf54Spim, 131_072>> = StaticCell::new();
static NET: StaticCell<nrf70::EthernetState<4, 4>> = StaticCell::new();

let resources = RESOURCES.init(nrf70::Resources::new());
let platform = PLATFORM.init(nrf70::Platform::new(MyNrf54Spim::new(/* owned pins */)));
let net_state = NET.init(nrf70::EthernetState::new());
let (wifi, runner, device, host_irq) =
    nrf70::new_with_data_plane(resources, platform, net_state);
spawner.spawn(wifi_runner(runner))?;

wifi.initialize(mac, nrf70::Country::new(*b"US")?).await?;
let mut ssid = heapless::Vec::new();
ssid.extend_from_slice(b"lab-5g").unwrap();
wifi.connect(nrf70::ConnectRequest {
    ssid,
    credential: nrf70::Credential::Passphrase(
        nrf70::PassphraseBuf::new(b"correct horse battery staple")?,
    ),
    band: nrf70::BandPolicy::FiveGhzOnly,
    country: nrf70::Country::new(*b"US")?,
    bssid: None,          // picked by a 5 GHz SSID-filtered scan (best RSSI)
    frequency_mhz: None,
    mfp: nrf70::Mfp::Optional,
}).await?;
// `Ok(())` (and `LinkEvent::Up`) means the link is usable: for secured
// sessions it is reported only after the 4-way handshake completes and the
// controlled port is authorized. Pass `device` to embassy-net.
```

`Bus::power_on/off` must implement the reviewed board power contract. Bulk bus
operations receive four-byte-aligned addresses, buffers, and lengths. Use
blocking SPIM only; never bridge a C callback to an async future.

## Phase-3 scope and security notes

- WPA2-Personal with CCMP/AES only (passphrase or raw 32-byte PSK), plus open
  networks. WPA2-PSK-SHA256 APs are supported: the AKM is actually chosen
  from the AP's RSN IE by the supplicant, and mixed PSK/PSK-SHA256 APs use
  plain PSK. WPA2/WPA3 transition-mode APs are supported via WPA2, even
  when display scans label them as WPA3. The connect scan validates the
  actual RSN IE for a PSK AKM and CCMP group/pairwise ciphers before
  association; SAE-only APs are rejected (`Error::HandshakeFailed`).
  SAE itself is not implemented. Required-PMF interoperability remains
  unqualified on hardware; the tested configuration uses optional PMF.
- `Bus::random_u8` is the sole entropy source for WPA2 nonce generation (the
  EAPOL-Key SNonce) and MUST be backed by a cryptographically secure TRNG
  (the CRACEN-backed entropy service on the target board); a counter or weak
  PRNG there breaks the 4-way handshake's security. The op is mandatory —
  the C side substitutes a constant 0 when it is missing.
- The connect state machine (sliced PBKDF2 PMK derivation, connect scan,
  open-system auth, associate with the supplicant RSN IE, EAPOL 4-way
  handshake, controlled-port authorization) lives entirely in the C facade;
  Rust drives it with one `connect_start` call and consumes events.
- EAPOL rides the normal data path at this `nrf_wifi` pin: there is no
  control-port TX command, so EAPOL TX goes through `nrf_wifi_fmac_start_xmit`
  as an ordinary `0x888E` Ethernet frame, and the facade diverts `0x888E` RX
  frames to the supplicant before the Ethernet queue (the Rust RX pump also
  defensively drops any `0x888E` frame). Non-EAPOL data frames are dropped
  until the port is authorized (`rx_dropped_unauthorized`).
- Secrets are zeroized and never logged: `PassphraseBuf`/`Credential` wipe on
  drop, credentials reach the runner through a dedicated stash slot (never
  the command channel's queue storage) and are zeroized in that slot right
  after `connect_start` consumes them, the facade
  zeroizes its own staging when the PMK is derived and on any teardown, and
  the supplicant keeps only the PMK (for rekeying) until disconnect, abort,
  reset, or deinit. `Debug` for credentials prints a redacted placeholder.
- Open connects time out after 10 s, secured connects after 30 s
  (`SECURE_CONNECT_TIMEOUT_US`); timeout and cancellation use
  `connect_abort`, which tears down supplicant state and zeroizes secrets.

## Phase-2 scope (unchanged)

- Pinned full system-mode `nrf_wifi` sources and matching default `nrf70.bin`.
  The facade drives FMAC directly; it does not use the scan-only `nrf70-bm`
  public API (only its common board/firmware helper code remains as a pinned
  porting component).
- One station VIF, 5 GHz scan, link and disconnect events, power save, TX/RX,
  statistics, and generation-based reset.
- Bounded C RX queue (4), small FMAC TX/RX configuration, and application-sized
  Embassy queues.

Hardware exit testing remains required: repeated WPA2 connects, reconnects,
wrong-password failures, AP rekeys, deauthentication, and AP power cycles
against unrelated AP implementations, plus the Phase-2 load, queue-exhaustion,
and reset tests on the target board.
