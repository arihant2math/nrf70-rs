# nRF7002 5 GHz Wi-Fi from Rust on nRF54LM20A

## Goal

Add 5 GHz-only nRF7002 station support to the bare-metal Rust/Embassy MCU
firmware. In border mode it must run concurrently with the nRF54LM20A's
IEEE 802.15.4 radio and Thread stack.

The first production target is:

- 5 GHz Wi-Fi station mode
- WPA2-Personal, followed by WPA3-Personal/PMF
- an Ethernet-frame interface usable by `embassy-net`
- DHCPv4 and IPv6 connectivity
- nRF7002 sleep/shutdown and deterministic recovery
- concurrent Wi-Fi and Thread traffic in border mode

SoftAP, P2P, Enterprise authentication, WEP, WPA1, and 2.4 GHz Wi-Fi are out of
scope.

## Feasibility and the important catch

This is feasible, but it is not only a bindgen task. The nRF7002 is a companion
FullMAC device: it runs the time-critical PHY/MAC firmware, while the host still
runs all of the following:

1. the nRF70 bus, HAL, and FMAC driver
2. a WPA supplicant for authentication, association, key exchange, and roaming
3. an IP stack
4. for border mode, the Thread infrastructure-interface and routing logic

There is currently no production-ready, complete bare-metal Rust nRF7002 stack
to adopt:

- `embassy-rs/nrf70` is a useful protocol reference, but its current prototype
  is incomplete: QSPI is disabled in its example, TX initialization is empty,
  and much of event and command processing is unfinished. Do not make it the
  production dependency.
- Nordic's `nrf70-bm` is the best bare-metal porting reference, but its public
  functionality is deliberately limited to scan and radio-test modes. It does
  not provide normal station connectivity.
- Nordic's complete and tested station path is the OS-agnostic C `nrf_wifi`
  driver plus Zephyr glue and a Zephyr port of `wpa_supplicant`.

The recommended implementation therefore keeps the application, ownership,
async orchestration, IP stack, and product logic in Rust, while compiling the
pinned Nordic C driver and a narrowly configured C supplicant behind safe Rust
APIs.

```text
Rust application / border-router tasks
  -> embassy-net                         (IP endpoints)
  -> safe async nrf70 crate              (control + Ethernet frame device)
     -> nrf70-sys C facade
        -> WPA supplicant STA subset
        -> Nordic OS-agnostic nrf_wifi FMAC/HAL
        -> nRF7002 system firmware patch
        -> Rust-owned OSAL and SPIM callouts
           -> dedicated nRF54LM20A SPIM + GPIO HOST_IRQ/BUCKEN/IOVDD
```

A new supplicant written specifically for this product is not recommended.
WPA2's four-way handshake and especially WPA3 SAE/PMF are security-sensitive,
and there is not yet a mature production `no_std` Rust supplicant suitable for
this target.

## Hardware decision: use dedicated SPIM first

Use the nRF7002's four-wire SPI host interface for the first board and driver.
Do not share this bus with the MAX78002, even though ordinary low-rate sensors
can share an SPI bus. Wi-Fi transfers and nRF70 event servicing must not be
blocked behind long NPU transactions.

Allocate and own:

- one dedicated SPIM instance
- SCK, CSN, MOSI, and MISO
- `HOST_IRQ`, configured as an edge-to-active GPIO interrupt
- `BUCKEN`
- `IOVDD_CTL` if the board has a switched I/O rail
- optional coexistence pins or at least test pads for them

The official nRF7002 EB II connection to the nRF54LM20 DK uses SPI at 8 MHz.
The nRF7002 host interface can operate faster, but the actual limit must be
validated against the chosen nRF54LM20A SPIM instance and the custom PCB's
signal integrity. Start at 8 MHz, then qualify 16 MHz and 32 MHz. In the current
`embassy-nrf` target, `SERIAL20..22` are limited to 16 MHz while `SERIAL00` can
use the 128 MHz source; reserve `SERIAL00` if 32 MHz is a product requirement.

Do not use nRF54L sQSPI for initial bring-up. It requires a second licensed
firmware image, the FLPR/VPR resource, about 16 KB of specially placed/retained
RAM, and additional ownership and low-power work. It also has not yet been
proven with this Rust MPSL/802.15.4 integration. It can be evaluated later only
if SPI throughput is inadequate.

The board must be laid out and calibrated as a 5 GHz radio product. The driver
configuration needs measured per-sub-band 5 GHz TX power ceilings for this PCB;
Nordic's DK/EB values must not be copied into a production board without RF
verification.

Before the schematic is frozen, check in one combined resource table covering
Wi-Fi, the NPU, sensors, MPSL/802.15.4, and both boot modes. It must assign exact
SERIAL instances, pins, GPIOTE channels, EasyDMA-accessible RAM, interrupt
priorities, CRACEN access, and power-control lines. The provisional choice is
`SERIAL00` for nRF7002 and another SERIAL instance for MAX78002. This deliberately
replaces `spec/STACK.md`'s single-shared-SPI assumption; update that document once
the schematic assignment is accepted.

## Phase 0: prove the hardware with Nordic's supported stack

Before porting code, use an nRF54LM20 DK plus nRF7002 EB II to build Nordic's
NCS station and Thread/Wi-Fi coexistence samples.

Tests must include:

- a 5 GHz-only scan
- WPA2 and WPA3 association
- DHCPv4 and IPv6 traffic
- sustained Wi-Fi plus Thread traffic
- nRF7002 sleep, shutdown, wake, and repeated power cycles
- the selected SPI frequencies

Record the exact pin map, SPI mode/frequency, IRQ behavior, firmware patch,
country configuration, memory footprint, throughput, packet-loss rate, and
current. Also copy the nRF7002 data-sheet power sequence into a checked-in board
contract: IOVDD/BUCKEN ordering and delays, inactive GPIO levels that prevent
back-powering, HOST_IRQ pull behavior, deinit/reset order, and the state of every
pin while the device is off. This baseline separates board/RF problems from
Rust port problems.

Freeze one mutually tested set of revisions for:

- `sdk-nrf`
- `sdk-zephyr`
- `zephyrproject-rtos/nrf_wifi`
- `sdk-nrfxlib` nRF70 firmware patch
- Zephyr's hostap/wpa_supplicant module
- `embassy-nrf`, `embassy-net`, `embassy-net-driver-channel`, `nrf-mpsl`, and
  the future `nrf_802154` fork
- OpenThread and its exact device/border-router build configuration
- the WPA crypto backend used by the baseline, including its configuration

The `nrf_wifi` source and the `nrf70.bin` system firmware patch must remain a
versioned pair. Check in a manifest containing URLs, commits, hashes, licenses,
and the selected compile-time configuration. Preserve BSD-3-Clause notices and
Nordic's LicenseRef-Nordic-5-Clause terms for firmware binaries.

Do the first per-mode RAM and RRAM budget here, not after the port. Any Wi-Fi control allocation must use
a separately budgeted, bounded arena sized from measurements. Rust statics from
mutually exclusive runtime branches do not automatically overlay. Reserve RRAM pages for
a versioned settings journal now; `mcu/memory.x` currently gives essentially all
RRAM to the application and cannot provide atomic credentials or a Thread
dataset. The storage design needs page boundaries, two-phase commit, sequence,
CRC/MAC policy, wear behavior, and power-failure tests.

Select one entropy/crypto ownership design as part of the resource map. The
preferred design is a Rust entropy service which exclusively owns CRACEN/TRNG
and supplies bytes to 802.15.4, the supplicant, and protocol stacks through
bounded calls. SDC may own CRACEN directly only in the mutually exclusive BLE
provisioning boot. The pinned WPA crypto backend, rather than ad-hoc Rust and C
mixtures, supplies PBKDF2, AES, SHA/HMAC, ECC/SAE, and PMF primitives.

**Exit condition:** official NCS firmware passes 5 GHz and concurrent
Thread/Wi-Fi tests on the intended electrical interface; every dependency
revision is pinned; resource, storage, crypto, and per-mode memory maps have
passed review.

## Phase 1: create a scan-only Rust binding

Create two crates outside the application crate:

```text
nrf70-rs/
├── nrf70-sys/ C build, private generated bindings, stable C facade
└── nrf70/     safe async Rust API and Embassy adapter
```

Use `nrf70-bm` and its Zephyr shim as porting references. Build its scan-only
subset and the matching scan firmware patch first. This avoids attempting
supplicant and data-plane work before the bus and platform layer are stable.

### Stable C facade

Do not bind every internal FMAC struct directly into application Rust. Internal
headers are configuration-sensitive and change frequently. Add a small C
facade with fixed-width inputs and outputs for:

- global/device initialization and deinitialization
- event processing
- setting the country/regulatory domain
- starting and cancelling a band/channel-filtered scan
- scan-result and scan-complete callbacks
- statistics and fatal-error reporting

Generate private bindings to that facade with the same target defines and
compiler flags used to compile the C sources. Include C/Rust size, alignment,
and enum-value assertions in the build.

Compile for `thumbv8m.main-none-eabihf`, Cortex-M33, hard float, and the same
enum-width setting on both sides. Fail the build when Clang, the pinned source,
the matching firmware blob, or required license files are absent.

### Rust-owned platform layer

Implement the `nrf_wifi_osal_ops` required by the selected source revision.
Treat the source revision's complete ops table and link-time undefined-symbol
inventory as the checklist. It includes at least:

- memory allocation and memory operations
- SPI register and bulk transfers
- linked lists and network buffers
- locks/critical sections
- tasklet scheduling
- timers, delays, and monotonic time
- logging, assertions, and random bytes supplied by the shared entropy service
- host interrupt registration

All nRF70 C code must execute in one serialized **thread-mode** Embassy driver
task. Do not run FMAC, the supplicant, PBKDF2/SAE, OSAL sleeps, or bulk SPI from
an `InterruptExecutor`; Handler-mode yielding can tail-chain and starve every
normal Rust task. Normal application tasks submit bounded commands and never
call FMAC synchronously.

This still leaves a scheduling gate: a synchronous C call blocks the cooperative
thread executor even though MPSL's hardware interrupts can preempt it. During
Phase 1, instrument the maximum duration of every C entry point, OSAL delay, and
SPI transfer under IRQ load. Give event draining a count/time budget and yield
between C calls. The scheduling spike must either (a) prove that
`nrf-mpsl::run` can safely execute from a dedicated, higher-priority Embassy
context exactly as required by the pinned MPSL, or (b) refactor long nRF70
operations/delays into restartable state-machine steps. Wi-Fi integration stops
if measured thread blocking exceeds MPSL's low-priority service deadline; moving
the whole Wi-Fi stack into Handler mode is not the workaround.

`HOST_IRQ` is edge-woken but level-drained. Its ISR only sets a signal; it must
not call C or perform SPI. After waking, the driver drains a bounded number of
events, yields, and repeats while the line is active. It checks the GPIO level
again after arming the wait and before sleeping so an already-asserted or
lost-edge condition cannot strand events.

The driver task serializes commands, IRQ event draining, tasklets, and timer
callbacks. Synchronous C callbacks may only copy/enqueue an event and return;
they may not call back into FMAC or the supplicant. The outer runner processes
queued callbacks only after the initiating C call has unwound. Add a debug
re-entry guard and bounded event/time budgets.

C bus callbacks are synchronous, so use blocking SPIM operations only from the
driver task. Never wait for an async Embassy future from a C callback. Enforce
alignment and length restrictions at the bridge and test the
RDSR0/RDSR1/RDSR2, system-bus, peripheral-bus, and packet-RAM operations from
Nordic's bus test.

Use bounded static pools initially:

- a fixed control allocation arena with high-water and failure counters
- fixed linked-list/tasklet/timer slots
- fixed, aligned network-buffer pools

If the supplicant later requires a general allocator, give the C Wi-Fi stack a
dedicated bounded TLSF arena rather than the application's unconstrained global
heap. An allocation failure must produce a recoverable driver error or a
controlled radio reset, never memory corruption.

### Safe scan API

The safe crate owns the SPIM and all nRF7002 GPIO tokens and initializes one
device once. Expose only owned Rust results:

```rust
wifi.scan(ScanRequest {
    band: Band::FiveGhz,
    country,
    channels,
    ssid_filter,
}).await
```

Copy scan results out of C-owned memory during the callback. Use bounded queues
and count dropped results.

**Exit condition:** Rust firmware repeatedly powers the nRF7002, downloads the
scan patch, sees known 5 GHz APs, enters sleep/shutdown, and recovers after
hundreds of reset and power-gate cycles without leaks or deadlocks.

## Phase 2: port the complete FMAC data plane

Replace the scan-only build with the pinned `nrf_wifi` system-mode sources and
matching default `nrf70.bin` patch. Do not continue to use `nrf70-bm`'s public
API here; it intentionally exposes only scan and radio-test functionality.

Phase 2 uses an open laboratory AP only. Include the minimum open-network MLME
control path needed to scan/authenticate/associate, and delete that test shortcut
once the supplicant owns connection policy. WPA-protected traffic is not an exit
criterion until Phase 3.

The C facade now needs operations and callbacks for:

- virtual-interface creation/removal
- scan/authenticate/associate/disconnect control
- key installation and controlled-port authorization
- Ethernet-frame TX and completion
- Ethernet-frame RX and buffer release
- link state, RSSI, channel/frequency, reason codes, and fatal firmware events
- power save, statistics, and device reset

Adapt the data plane to `embassy-net-driver-channel` with 1514-byte Ethernet
frame buffers, corresponding to a 1500-byte IP MTU and excluding the FCS.
Initially copy between the C nbuf pool and Rust channel buffers; do not attempt
zero-copy across FFI until ownership is proven. TX storage stays valid until
completion, and each RX buffer is returned exactly once.

Use small, measurable queue depths suited to sensor and border-router traffic,
not Nordic's throughput-demo defaults. Expose counters for every pool, queue,
copy, drop, timeout, firmware restart, and SPI error.

**Exit condition:** the driver can exchange Ethernet frames under sustained
load, including queue exhaustion and forced nRF7002 reset tests, with no stale
pointers, double frees, or driver-task starvation.

## Phase 3: WPA supplicant

Port the minimum STA-only subset of the same hostap/wpa_supplicant revision used
by the Phase 0 baseline. Keep it behind another narrow facade instead of
exposing hostap internals to Rust.

The first configuration supports only:

- open networks for laboratory testing
- WPA2-Personal with CCMP/AES
- one station interface and one saved network
- explicit EAPOL demultiplexing and FMAC control-port TX

Compile out AP, P2P, WPS, Enterprise EAP methods, WEP, WPA1/TKIP, command-line
control sockets, POSIX sockets, files, and dynamic configuration parsing.
Implement its event loop, timers, entropy, allocator, logging, and driver ops on
the same serialized Wi-Fi context. EtherType `0x888e` RX frames bypass the
unauthorized controlled port and go to the supplicant before `embassy-net`;
EAPOL TX uses FMAC's control-port operation. Ordinary data is dropped/held until
the supplicant authorizes the controlled port. Use the pinned Phase 0 crypto
backend through one well-defined facade; do not invent protocol crypto.

Once WPA2 is stable, enable WPA3-Personal SAE and mandatory Protected Management
Frames. WPA3 is part of the production definition of done unless deployment
requirements explicitly restrict all APs to WPA2.

The Rust control API should look like:

```rust
wifi.connect(ConnectRequest {
    ssid,
    credential,
    band: BandPolicy::FiveGhzOnly,
    country,
}).await
```

It returns structured events and reason codes rather than C pointers or integer
status values. Secret material must be zeroized when transient storage is
released and must never appear in `defmt` output.

**Exit condition:** repeated WPA2 and WPA3 connects, reconnects, wrong-password
failures, AP rekeys, deauthentication, and AP power cycles pass against at least
three unrelated AP implementations.

## Phase 4: enforce 5 GHz as an invariant

A 5 GHz preference is insufficient. A dual-band SSID can otherwise reconnect or
roam onto 2.4 GHz and interfere with the Thread radio.

Enforce the policy at all layers:

1. Require a provisioned ISO 3166-1 alpha-2 country code; do not ship with the
   world domain.
2. Initialize FMAC for the 5 GHz operating band only where the pinned API allows
   it.
3. Generate scan channel lists exclusively from legal 5 GHz channels for that
   country.
4. Reject 2.4 GHz scan candidates before association.
5. Disable or constrain roaming so it cannot change bands.
6. Verify the reported association frequency after connect and after every
   roam/channel event; disconnect on violation.
7. Initially avoid DFS channels to simplify bring-up, then add them only after
   regulatory and AP interoperability testing.
8. Test with one SSID advertised simultaneously on 2.4 and 5 GHz and with the
   5 GHz BSS disappearing while 2.4 GHz remains available.

Leave nRF70 2.4 GHz coexistence disabled only after this invariant is proven.
Populate coexistence test points on the PCB so a future 2.4 GHz requirement does
not force an immediate board revision.

**Exit condition:** conducted/sniffer tests show no nRF7002 2.4 GHz
transmissions during boot, scan, association, reconnect, or fault recovery.

## Phase 5: firmware integration and boot modes

Refactor mode selection before integrating Wi-Fi. The current `main.rs`
constructs MPSL and consumes SDC/CRACEN resources before it has loaded a mode;
the new boot first reads and validates the settings journal, then constructs
only the resources required by that branch. Replace `OperationMode` with
separate topology, uplink, mesh transport, and mesh-role fields, then reject
invalid cross-field combinations during profile validation.

Add `mcu/src/wifi.rs` only after the safe crate works in a standalone hardware
test. Extend persistent provisioning with bounded, versioned fields for:

- SSID
- WPA2/WPA3 credential type and secret
- country code
- optional allowed 5 GHz channel set or BSSID
- Wi-Fi power policy
- Thread operational dataset for border mode

Remove `String` and obsolete WEP/WPA1 options from persisted embedded config.
Use bounded byte arrays, validate lengths and UTF-8 policy explicitly, and
commit credentials atomically using the Phase 0 settings journal.

Wi-Fi credentials also require a real provisioning security design; the current
GATT server exposes only a Battery Service. Define a versioned GATT protocol
with framing/reassembly, validation, commit acknowledgement, and reset behavior.
Require authenticated LE Secure Connections plus an explicit authorization or
physical-presence policy before accepting secrets. Define credential-at-rest,
debug-port/readback-protection, factory-reset, and log-redaction policy before
shipping provisioning code.

Boot behavior should be:

```text
unprovisioned:
  MPSL + SDC + TrouBLE provisioning
  nRF7002 held in shutdown

isolated Wi-Fi:
  no SDC/TrouBLE
  nRF7002 + supplicant + embassy-net
  initialize MPSL only if another active mode actually requires it

meshed Thread node:
  MPSL + nrf_802154 + Thread
  nRF7002 held in shutdown

border router (mains present only):
  MPSL + nrf_802154 + Thread FTD/router
  nRF7002 + supplicant + infrastructure IP stack
```

Keep reset as the transition boundary after BLE provisioning. `BUCKEN` remains
low in modes that do not use Wi-Fi. In Wi-Fi modes, use associated power save
for normal idle periods and full deinit/shutdown only for long outages or mode
changes. Every physical power-off and every logical recovery (firmware
watchdog, SPI-fault reset, FMAC deinit/reinit) first disables callback ingress,
increments a generation counter, fails pending control/TX/RX futures, releases
or invalidates all nbufs and queued completions, tears down supplicant/VIF/key
and controlled-port state, and only then recreates a clean generation. Physical
power changes additionally follow the board's IOVDD/BUCKEN contract.

Enforce `spec/OPERATION.md`'s mains rule in code: border mode and OpenThread
router eligibility are enabled only while validated mains power is present. A
battery meshed device is a sleepy/end device and never advertises router
capability. Define and test the mains-loss policy before implementation; the
safe default is to stop accepting routed work, persist necessary state, shut
Wi-Fi down, and reset into non-router mesh mode rather than silently routing on
battery.

The nRF7002 is external and can operate concurrently with the internal radio;
this does not change the separate decision that BLE and IEEE 802.15.4 are never
constructed at the same time.

**Exit condition:** all four persisted modes select exactly their intended
stacks and hardware resources, and factory reset reliably returns to BLE-only
provisioning.

## Phase 6: IP and Thread border routing

For ordinary isolated Wi-Fi operation, run `embassy-net` over the nRF70 Ethernet
device and validate DHCPv4, IPv6, DNS, UDP, TCP, and application TLS separately.

A Thread border router is not completed by creating a second `embassy-net`
instance, and one `embassy-net-driver-channel` cannot be independently consumed
by both `embassy-net` and OpenThread. Put one Rust `WifiL2Mux` in sole ownership
of nRF70 RX/TX. In isolated mode it sends EAPOL to the supplicant and ordinary
frames to `embassy-net`. In border mode it additionally owns the infrastructure
IPv6/router path and demultiplexes host-local, control/ND, forwarded-unicast,
and required multicast traffic.

Before implementing the full router, make an architecture spike prove the exact
OpenThread packet injection/extraction APIs used by the pinned revision. Select
and document either a custom bounded Rust IPv6 forwarder around those APIs or a
portable OpenThread platform L2 integration; do not assume `otPlatInfraIf*`
forwards data packets. The design must include Ethernet neighbor resolution,
IPv6 hop-limit decrement, ICMPv6 errors, route lookup/installation, Wi-Fi-to-OMR
and mesh-to-infrastructure injection, and multicast forwarding. If those packet
hooks cannot be provided without importing Zephyr's network stack, treat that
as a stop gate rather than writing an implicit partial router.

Integrate the selected OpenThread build's Border Routing Manager for control
plane and implement its infrastructure interface over `WifiL2Mux`, including:

- infrastructure-interface state and address queries
- ICMPv6 Neighbor Discovery receive/send hooks
- Router Advertisement processing and emission
- on-link and OMR prefix handling
- route publication to Thread
- multicast behavior required by the selected Thread profile

The Border Routing Manager's `InfraIf`/ND hooks manage infrastructure control
and prefix state; they do not replace the explicit forwarding data plane above.
Start with an IPv6-capable Wi-Fi upstream. NAT64/DNS64 for an IPv4-only upstream
is a separate milestone and must not be hidden inside the nRF7002 binding work.

**Exit condition:** a sleepy Thread end device reaches an IPv6 host through the
5 GHz Wi-Fi infrastructure and remains connected during sustained bidirectional
Wi-Fi/Thread traffic and AP reconnects.

## Memory and image budget

Measure the final ELF; do not rely only on component estimates. Nordic's
published station examples are useful warning signs:

- the system nRF70 firmware patch is roughly 80--90 KB of image storage
- the C Wi-Fi driver is roughly 50--60 KB ROM and about 60--90 KB RAM depending
  on queue configuration
- the WPA supplicant is roughly 150 KB ROM and about 40 KB RAM
- an official nRF54L station sample is already around 0.5 MB before this
  product's Rust application, OpenThread, border routing, and sensor code

Therefore the `<0.5 MB` firmware hope in `spec/STACK.md` is not a realistic
planning assumption for a combined border-router image. The 2 MB RRAM should be
adequate for one image, but dual-slot OTA may not be. Produce a partition and
OTA plan only after measuring the release build.

The first version of this budget is a Phase 0 exit criterion; update it with measured ELF/stack/pool values at
every later phase.

For RAM, check all of the following together:

- MPSL's reserved top-of-SRAM region
- `nrf_802154` and OpenThread
- nRF70 control and data arenas
- supplicant arena
- Embassy executor/task storage
- `embassy-net` socket and packet storage
- application and NPU buffers

Add link-time region assertions, stack canaries, allocator high-water marks, and
pool high-water marks. A final border image must retain at least a documented
fault/recovery margin rather than merely linking within 512 KB.

## Validation matrix

### Build and ABI

- release build for `thumbv8m.main-none-eabihf`
- every Nordic/Zephyr source and binary pinned by revision and hash
- matching `nrf_wifi` source and nRF70 firmware patch
- no accidental Zephyr kernel, POSIX, filesystem, or libc dependencies
- C/Rust facade size, alignment, enum, and callback calling-convention tests
- no unresolved OSAL symbols
- map-file ROM/RAM budgets and arena/pool sizes checked in CI
- license notices included in binary distribution materials

### Bus and lifecycle

1. Nordic register/bus test suite at 8, 16, and selected production MHz.
2. Firmware download and init/deinit loops.
3. HOST_IRQ storms, already-high IRQ at enable, lost-edge windows, and bounded
   level-drain behavior.
4. BUCKEN shutdown during idle, scan, TX, and RX, followed by recovery.
5. SPI timeout, stuck IRQ, corrupted event, firmware watchdog, and AP outage.
6. IOVDD/BUCKEN sequencing with no pin back-powering and all outstanding
   futures cancelled by reset generation.
7. Thousands of warm resets and hundreds of hard power cycles.

### 5 GHz and security

1. Scan only legal 5 GHz channels for several country domains.
2. Dual-band same-SSID test proves no 2.4 GHz association or fallback.
3. WPA2 CCMP and WPA3 SAE/PMF success and failure cases.
4. Rekey, deauth/disassoc, wrong credential, hidden SSID, and roaming tests.
5. DFS behavior only after the non-DFS matrix passes.
6. Packet capture verifies EAPOL, controlled-port, and no-secret-log behavior.

### Data and power

1. DHCPv4 and IPv6 address acquisition.
2. UDP/TCP in both directions at target packet sizes and rates.
3. Queue exhaustion with explicit drop/backpressure counters.
4. 24-hour traffic soak with AP restarts.
5. Active, associated power-save, disconnected, sleep, and shutdown current.

### Concurrent border mode

1. MPSL/802.15.4 timing tests while downloading the nRF70 patch.
2. Sustained Wi-Fi RX/TX plus acknowledged Thread RX/TX.
3. Wi-Fi reconnect while a sleepy Thread child remains attached.
4. No starvation of RADIO, MPSL, GRTC, or nRF70 HOST_IRQ processing.
5. End-to-end IPv6 routing from Thread through 5 GHz Wi-Fi, including hop-limit,
   neighbor-cache, ICMPv6 error, route-change, and multicast cases.
6. Mains removal proves the device stops router operation and never routes on
   battery.

## Main risks and gates

- **Supplicant port scope:** this is the largest software risk. Before Phase 2,
  compile the pinned STA-only hostap subset outside Zephyr and inventory every
  required platform symbol. If it still requires a substantial Zephyr/POSIX
  compatibility layer, stop and compare moving the whole MCU image to NCS or
  using a true Wi-Fi network coprocessor. Do not bury a second RTOS under FFI.
- **Driver/firmware drift:** pin and hash the pair, and test the final hardware
  image rather than accepting a successful `cargo check`.
- **Synchronous C versus async Rust:** isolate all C and blocking SPI work in one
  thread-mode driver task. Callbacks signal/copy only and never await. The Phase
  1 latency spike must prove MPSL low-priority servicing remains schedulable or
  force long C operations to be split into restartable steps.
- **Memory pressure:** tune bounded queues from measured border traffic. Never
  copy Nordic throughput-sample heaps into the product without a budget.
- **5 GHz fallback bugs:** enforce and continuously verify the associated band;
  SSID preference alone is not a safety mechanism.
- **sQSPI distraction:** remain on SPIM unless measured throughput fails a
  written requirement. A later sQSPI experiment must first prove FLPR, RAM,
  MPSL, and low-power coexistence.
- **Bindings mistaken for a border router:** raw bus, scan, FMAC data, WPA,
  L2 demultiplexing, local `embassy-net`, IPv6 forwarding, and OpenThread border
  routing are separate acceptance gates.

## Definition of done

A release Rust firmware on nRF54LM20A can be provisioned over BLE, reset into
border mode, power and initialize an nRF7002 over dedicated SPI, associate only
on a legal 5 GHz channel using WPA2 or WPA3, maintain IPv4/IPv6 traffic, and
route IPv6 traffic between a Thread sleepy end device and the Wi-Fi
infrastructure. It passes sustained concurrent Thread/Wi-Fi, power-cycle,
band-fallback, memory-pressure, and recovery tests without enabling BLE and
IEEE 802.15.4 concurrently or transmitting nRF7002 traffic in 2.4 GHz.
