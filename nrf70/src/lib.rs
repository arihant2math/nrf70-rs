#![no_std]

mod arena;
mod platform;
mod spi;
pub use arena::Arena;
pub use embassy_net_driver_channel::Device as EthernetDevice;
pub use platform::{Bus, Platform};
pub use spi::{BoardControl, SpiTransport};

use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use embassy_net_driver_channel::{
    self as net_channel,
    driver::{HardwareAddress, LinkState},
};
use embassy_sync::{
    blocking_mutex::{Mutex as BlockingMutex, raw::CriticalSectionRawMutex},
    channel::Channel,
    signal::Signal,
};
use embassy_time::{Duration, Timer};
use heapless::Vec;
use zeroize::Zeroize;

pub const MAX_SCAN_RESULTS: usize = 64;
pub const EVENT_DRAIN_BUDGET: u32 = 8;
pub const ETHERNET_FRAME_SIZE: usize = 1514;
pub const OPEN_CONNECT_TIMEOUT_US: u32 = 10_000_000;
/// Secured sessions cover PMK derivation, the connect scan, auth/assoc, and
/// the 4-way handshake, so they get a longer budget than open connects.
pub const SECURE_CONNECT_TIMEOUT_US: u32 = 30_000_000;
const EAPOL_ETHERTYPE: [u8; 2] = [0x88, 0x8e];
pub type EthernetState<const RX: usize, const TX: usize> =
    net_channel::State<ETHERNET_FRAME_SIZE, RX, TX>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Band {
    FiveGhz,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Country([u8; 2]);
impl Country {
    pub fn new(code: [u8; 2]) -> Result<Self, Error> {
        if code.iter().all(|b| b.is_ascii_uppercase()) {
            Ok(Self(code))
        } else {
            Err(Error::InvalidCountry)
        }
    }
    pub const fn bytes(self) -> [u8; 2] {
        self.0
    }
}
#[derive(Clone, Debug)]
pub struct ScanRequest {
    pub band: Band,
    pub country: Country,
    pub channels: Vec<u8, 32>,
    pub ssid_filter: Vec<u8, 32>,
    pub passive: bool,
    pub dwell_active_ms: u16,
    pub dwell_passive_ms: u16,
    pub max_results: u16,
}
impl ScanRequest {
    pub fn five_ghz(country: Country) -> Self {
        Self {
            band: Band::FiveGhz,
            country,
            channels: Vec::new(),
            ssid_filter: Vec::new(),
            passive: false,
            dwell_active_ms: 50,
            dwell_passive_ms: 130,
            max_results: 64,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Security {
    Open,
    Wpa2Personal,
    Wpa2Sha256,
    /// Firmware display label; may be SAE-only or WPA2/WPA3 transition mode.
    Wpa3Sae,
    Other,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessPoint {
    pub ssid: Vec<u8, 32>,
    pub channel: u8,
    pub rssi_dbm: i8,
    pub bssid: [u8; 6],
    pub security: Security,
    pub mfp: u8,
}

pub const fn channel_to_5ghz_frequency(channel: u8) -> Option<u16> {
    if channel >= 1 && channel <= 196 {
        Some(5000 + channel as u16 * 5)
    } else {
        None
    }
}

/// Phase 4 will widen this; today the driver is 5 GHz only by policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BandPolicy {
    FiveGhzOnly,
}
/// Protected Management Frames policy for the association.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mfp {
    Disabled,
    Optional,
    Required,
}
/// A WPA2 passphrase (8..=63 bytes). The bytes are zeroized on drop and are
/// never exposed through `Debug`/`defmt`.
pub struct PassphraseBuf {
    bytes: [u8; 63],
    len: u8,
}
impl PassphraseBuf {
    pub fn new(passphrase: &[u8]) -> Result<Self, Error> {
        if passphrase.len() < 8 || passphrase.len() > 63 {
            return Err(Error::InvalidRequest);
        }
        let mut bytes = [0u8; 63];
        bytes[..passphrase.len()].copy_from_slice(passphrase);
        Ok(Self {
            bytes,
            len: passphrase.len() as u8,
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}
impl Drop for PassphraseBuf {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.len = 0;
    }
}
/// Connection credential. Secret bytes are zeroized when the value is dropped
/// and are never logged; `Debug` prints a redacted placeholder.
pub enum Credential {
    Open,
    Passphrase(PassphraseBuf),
    /// A raw 32-byte PMK (the PBKDF2 output for WPA2-Personal).
    Psk([u8; 32]),
}
impl Drop for Credential {
    fn drop(&mut self) {
        // `PassphraseBuf` zeroizes itself in its own `Drop`.
        if let Credential::Psk(psk) = self {
            psk.zeroize();
        }
    }
}
impl core::fmt::Debug for PassphraseBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PassphraseBuf(..)")
    }
}
impl core::fmt::Debug for Credential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Credential(..)")
    }
}
/// One connect request. When `bssid` and `frequency_mhz` are not both given,
/// `connect` first scans (5 GHz, SSID-filtered) and picks the best-RSSI
/// compatible AP; whichever of the two is given filters the candidates, and
/// the connect frequency always comes from the picked AP's own channel.
#[derive(Debug)]
pub struct ConnectRequest {
    pub ssid: Vec<u8, 32>,
    pub credential: Credential,
    pub band: BandPolicy,
    pub country: Country,
    pub bssid: Option<[u8; 6]>,
    pub frequency_mhz: Option<u16>,
    pub mfp: Mfp,
}

/// Runner-ready connect parameters carrying raw credential bytes; zeroized on drop.
struct ConnectParams(nrf70_sys::ConnectTarget);
impl Drop for ConnectParams {
    fn drop(&mut self) {
        self.0.credential.zeroize();
        self.0.credential_len = 0;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Busy,
    InvalidCountry,
    InvalidRequest,
    NotInitialized,
    NoMemory,
    Io,
    Fatal,
    Cancelled,
    ResultOverflow,
    QueueFull,
    NotConnected,
    /// No scanned AP matched the requested SSID (and BSSID, when given).
    NotFound,
    /// No matching display-scan candidate fits the credential. WPA3-labelled
    /// candidates are checked for WPA2 transition mode during the connect
    /// scan; SAE-only RSN rejection is reported as `HandshakeFailed`.
    IncompatibleSecurity,
    /// The 4-way handshake failed; the 802.11 reason code is reported through
    /// an accompanying `LinkEvent::Down` (emitted even when the net link
    /// never rose during the attempt).
    HandshakeFailed,
    Timeout,
}
impl From<nrf70_sys::Status> for Error {
    fn from(e: nrf70_sys::Status) -> Self {
        match e {
            nrf70_sys::Status::Busy => Self::Busy,
            nrf70_sys::Status::Invalid => Self::InvalidRequest,
            nrf70_sys::Status::NotInitialized => Self::NotInitialized,
            nrf70_sys::Status::NoMemory => Self::NoMemory,
            nrf70_sys::Status::Io => Self::Io,
            nrf70_sys::Status::Cancelled => Self::Cancelled,
            nrf70_sys::Status::QueueFull => Self::QueueFull,
            nrf70_sys::Status::NotConnected => Self::NotConnected,
            nrf70_sys::Status::Fatal => Self::Fatal,
        }
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub c: nrf70_sys::Stats,
    pub dropped_results: u32,
    pub stale_events: u32,
    pub tx_channel_drops: u32,
    pub connect_timeouts: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkEvent {
    /// The link is usable. For secured sessions this is emitted only after
    /// the 4-way handshake completes and the controlled port is authorized.
    Up {
        frequency_mhz: u16,
        rssi_dbm: i8,
    },
    Down {
        reason_code: u16,
    },
    FirmwareRestart {
        generation: u32,
    },
    Fatal,
}

enum Command {
    Initialize {
        id: u32,
        mac: [u8; 6],
        country: Country,
    },
    Scan {
        id: u32,
        request: ScanRequest,
    },
    SetCountry {
        id: u32,
        country: Country,
    },
    /// The credentials travel out-of-band through `Resources::connect_stash`;
    /// the command itself carries no secret bytes.
    Connect {
        id: u32,
    },
    Disconnect {
        id: u32,
        reason: u16,
    },
    SetPowerSave {
        id: u32,
        enabled: bool,
    },
    Reset {
        id: u32,
    },
    Shutdown {
        id: u32,
    },
    Stats {
        id: u32,
    },
}
enum Response {
    Done { id: u32, result: Result<(), Error> },
    Result { id: u32, ap: AccessPoint },
    ScanDone { id: u32, result: Result<(), Error> },
    Stats { id: u32, stats: Stats },
}

pub struct Resources {
    commands: Channel<CriticalSectionRawMutex, Command, 2>,
    /// Pending connect credentials, handed to the runner out-of-band so no
    /// secret bytes are ever copied through (or linger in) the command
    /// channel's queue storage. The runner zeroizes the contents in place
    /// before clearing the slot. Residual risk: if the runner is never
    /// scheduled after `Wifi::connect` stashed a request, the credentials
    /// stay in this slot until it is next overwritten or scrubbed.
    connect_stash: BlockingMutex<CriticalSectionRawMutex, RefCell<Option<ConnectParams>>>,
    responses: Channel<CriticalSectionRawMutex, Response, 16>,
    events: Channel<CriticalSectionRawMutex, LinkEvent, 8>,
    irq: Signal<CriticalSectionRawMutex, ()>,
    wake: Signal<CriticalSectionRawMutex, ()>,
    cancel_id: AtomicU32,
    next_id: AtomicU32,
    busy: AtomicBool,
    dropped: AtomicU32,
    stale: AtomicU32,
    tx_drops: AtomicU32,
    timeouts: AtomicU32,
}
impl Resources {
    pub const fn new() -> Self {
        Self {
            commands: Channel::new(),
            connect_stash: BlockingMutex::new(RefCell::new(None)),
            responses: Channel::new(),
            events: Channel::new(),
            irq: Signal::new(),
            wake: Signal::new(),
            cancel_id: AtomicU32::new(0),
            next_id: AtomicU32::new(1),
            busy: AtomicBool::new(false),
            dropped: AtomicU32::new(0),
            stale: AtomicU32::new(0),
            tx_drops: AtomicU32::new(0),
            timeouts: AtomicU32::new(0),
        }
    }
}
impl Default for Resources {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
pub struct HostIrq<'a> {
    resources: &'a Resources,
}
impl HostIrq<'_> {
    /// Call from the GPIO ISR. It only signals thread mode and never invokes C or SPI.
    pub fn on_interrupt(&self) {
        self.resources.irq.signal(())
    }
}
pub struct Wifi<'a> {
    r: &'a Resources,
}
pub struct Runner<'a, B: Bus + Send + 'static, const N: usize> {
    r: &'a Resources,
    platform: &'static Platform<B, N>,
    net: Option<net_channel::Runner<'a, ETHERNET_FRAME_SIZE>>,
    initialized: bool,
    generation: u32,
    scan_id: Option<u32>,
    connect_id: Option<u32>,
    connect_deadline: u32,
    secured: bool,
    port_authorized: bool,
    /// A previous connect fully completed (open: link-up delivered; secured:
    /// the controlled port was authorized) and no teardown has happened since.
    /// Used to reject stale firmware carrier-up events that race an abort.
    session_established: bool,
    pending_link: Option<(u16, i8)>,
    linked: bool,
    last_reason: u16,
    mac: [u8; 6],
    country: Option<Country>,
    next_tx_token: u32,
}

fn make_runner<'a, B: Bus + Send + 'static, const N: usize>(
    r: &'a mut Resources,
    platform: &'static mut Platform<B, N>,
    net: Option<net_channel::Runner<'a, ETHERNET_FRAME_SIZE>>,
) -> (Wifi<'a>, Runner<'a, B, N>, HostIrq<'a>) {
    let r: &'a Resources = r;
    let platform: &'static Platform<B, N> = platform;
    (
        Wifi { r },
        Runner {
            r,
            platform,
            net,
            initialized: false,
            generation: 0,
            scan_id: None,
            connect_id: None,
            connect_deadline: 0,
            secured: false,
            port_authorized: false,
            session_established: false,
            pending_link: None,
            linked: false,
            last_reason: 0,
            mac: [0; 6],
            country: None,
            next_tx_token: 1,
        },
        HostIrq { resources: r },
    )
}
/// Creates the control/scan driver without an Ethernet adapter.
pub fn new<'a, B: Bus + Send + 'static, const N: usize>(
    r: &'a mut Resources,
    platform: &'static mut Platform<B, N>,
) -> (Wifi<'a>, Runner<'a, B, N>, HostIrq<'a>) {
    make_runner(r, platform, None)
}
/// Creates the complete FMAC driver and its 1514-byte Ethernet channel device.
pub fn new_with_data_plane<
    'a,
    B: Bus + Send + 'static,
    const N: usize,
    const RX: usize,
    const TX: usize,
>(
    r: &'a mut Resources,
    platform: &'static mut Platform<B, N>,
    state: &'a mut EthernetState<RX, TX>,
) -> (
    Wifi<'a>,
    Runner<'a, B, N>,
    EthernetDevice<'a, ETHERNET_FRAME_SIZE>,
    HostIrq<'a>,
) {
    let (net, device) = net_channel::new(state, HardwareAddress::Ethernet([0; 6]));
    let (wifi, runner, irq) = make_runner(r, platform, Some(net));
    (wifi, runner, device, irq)
}

struct Guard<'a> {
    r: &'a Resources,
    id: u32,
    armed: bool,
    cancel_on_drop: bool,
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        if self.cancel_on_drop && self.armed {
            self.r.cancel_id.store(self.id, Ordering::Release);
            self.r.wake.signal(())
        }
        self.r.busy.store(false, Ordering::Release)
    }
}
impl Wifi<'_> {
    fn guard(&self, cancel: bool) -> Result<Guard<'_>, Error> {
        self.r
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Busy)?;
        let id = self
            .r
            .next_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(1))
            .map_err(|_| {
                self.r.busy.store(false, Ordering::Release);
                Error::Fatal
            })?;
        Ok(Guard {
            r: self.r,
            id,
            armed: true,
            cancel_on_drop: cancel,
        })
    }
    async fn response(&self, id: u32) -> Response {
        loop {
            let response = self.r.responses.receive().await;
            let response_id = match &response {
                Response::Done { id, .. }
                | Response::Result { id, .. }
                | Response::ScanDone { id, .. }
                | Response::Stats { id, .. } => *id,
            };
            if response_id == id {
                return response;
            }
            self.r.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    async fn done(&self, g: &Guard<'_>) -> Result<(), Error> {
        match self.response(g.id).await {
            Response::Done { result, .. } => result,
            _ => Err(Error::Fatal),
        }
    }
    /// Runs a command that neither cancels on drop nor streams results: take
    /// the guard, send the command built from its id, await the single `Done`.
    async fn simple(&self, make: impl FnOnce(u32) -> Command) -> Result<(), Error> {
        let g = self.guard(false)?;
        self.r.commands.send(make(g.id)).await;
        self.done(&g).await
    }
    pub async fn initialize(&self, mac: [u8; 6], country: Country) -> Result<(), Error> {
        self.simple(|id| Command::Initialize { id, mac, country })
            .await
    }
    pub async fn set_country(&self, country: Country) -> Result<(), Error> {
        self.simple(|id| Command::SetCountry { id, country }).await
    }
    pub async fn scan(
        &self,
        request: ScanRequest,
    ) -> Result<Vec<AccessPoint, MAX_SCAN_RESULTS>, Error> {
        if request.channels.iter().any(|c| *c == 0 || *c > 196) || request.ssid_filter.len() >= 32 {
            return Err(Error::InvalidRequest);
        }
        let mut g = self.guard(true)?;
        self.r
            .commands
            .send(Command::Scan { id: g.id, request })
            .await;
        let mut out = Vec::new();
        loop {
            match self.response(g.id).await {
                Response::Result { ap, .. } => {
                    if out.push(ap).is_err() {
                        return Err(Error::ResultOverflow);
                    }
                }
                Response::ScanDone { result, .. } => {
                    g.armed = false;
                    return result.map(|_| out);
                }
                _ => return Err(Error::Fatal),
            }
        }
    }
    /// Scans 5 GHz for the request's SSID and picks the best-RSSI AP whose
    /// security fits the credential. Any given `bssid`/`frequency_mhz` only
    /// filters the candidates.
    async fn select_ap(&self, request: &ConnectRequest) -> Result<([u8; 6], u16, Security), Error> {
        let mut scan = ScanRequest::five_ghz(request.country);
        scan.ssid_filter = request.ssid.clone();
        let aps = self.scan(scan).await?;
        let mut best: Option<&AccessPoint> = None;
        let mut ssid_seen = false;
        for ap in aps.iter() {
            if ap.ssid != request.ssid {
                continue;
            }
            if let Some(wanted) = request.bssid
                && ap.bssid != wanted
            {
                continue;
            }
            if let Some(wanted) = request.frequency_mhz
                && channel_to_5ghz_frequency(ap.channel) != Some(wanted)
            {
                continue;
            }
            ssid_seen = true;
            #[cfg(feature = "defmt")]
            defmt::debug!("connect candidate: {}", defmt::Debug2Format(ap));
            if !credential_candidate(ap.security, &request.credential) {
                continue;
            }
            if best.is_none_or(|b| ap.rssi_dbm > b.rssi_dbm) {
                best = Some(ap);
            }
        }
        let Some(ap) = best else {
            return Err(if ssid_seen {
                Error::IncompatibleSecurity
            } else {
                Error::NotFound
            });
        };
        // The connect target frequency always comes from the
        // picked AP's own channel; a requested frequency only
        // filters the candidates above.
        let frequency_mhz = channel_to_5ghz_frequency(ap.channel).ok_or(Error::InvalidRequest)?;
        Ok((ap.bssid, frequency_mhz, ap.security))
    }
    /// Connects to a network. Open networks complete on link-up; secured
    /// networks (WPA2-Personal CCMP) complete once the supplicant finishes the
    /// 4-way handshake and authorizes the controlled port, so a returned
    /// `Ok(())` always means the link is usable. When `bssid`/`frequency_mhz`
    /// are not both given, a 5 GHz SSID-filtered scan picks the best-RSSI
    /// compatible AP first. Credential bytes are zeroized on every path and
    /// never logged.
    pub async fn connect(&self, request: ConnectRequest) -> Result<(), Error> {
        if request.ssid.is_empty() {
            return Err(Error::InvalidRequest);
        }
        let BandPolicy::FiveGhzOnly = request.band;
        let (bssid, frequency_mhz, security) = match (request.bssid, request.frequency_mhz) {
            (Some(bssid), Some(frequency_mhz)) => {
                if !(4900..=5900).contains(&frequency_mhz) {
                    return Err(Error::InvalidRequest);
                }
                let security = match &request.credential {
                    Credential::Open => Security::Open,
                    Credential::Passphrase(_) | Credential::Psk(_) => Security::Wpa2Personal,
                };
                (bssid, frequency_mhz, security)
            }
            _ => self.select_ap(&request).await?,
        };
        let mut ssid = [0u8; 32];
        ssid[..request.ssid.len()].copy_from_slice(&request.ssid);
        // One buffer for the secret bytes on every path, zeroized below once
        // the target has taken its copy.
        let mut credential = [0u8; 64];
        let (credential_kind, credential_len) = match &request.credential {
            Credential::Open => (nrf70_sys::CREDENTIAL_NONE, 0u8),
            Credential::Passphrase(p) => {
                credential[..p.as_bytes().len()].copy_from_slice(p.as_bytes());
                (nrf70_sys::CREDENTIAL_PASSPHRASE, p.as_bytes().len() as u8)
            }
            Credential::Psk(psk) => {
                credential[..32].copy_from_slice(psk);
                (nrf70_sys::CREDENTIAL_PSK, 32)
            }
        };
        let target = ConnectParams(nrf70_sys::ConnectTarget {
            ssid,
            ssid_len: request.ssid.len() as u8,
            bssid,
            frequency_mhz,
            security: match security {
                Security::Open => nrf70_sys::Security::Open,
                // Display scans label transition-mode APs as WPA3 too. Ask
                // the C connect scan to inspect their RSN IE for PSK support;
                // it must reject SAE-only APs before association.
                Security::Wpa2Personal | Security::Wpa3Sae => nrf70_sys::Security::Wpa2Psk,
                Security::Wpa2Sha256 => nrf70_sys::Security::Wpa2PskSha256,
                Security::Other => return Err(Error::IncompatibleSecurity),
            },
            mfp: match request.mfp {
                Mfp::Disabled => nrf70_sys::MFP_DISABLED,
                Mfp::Optional => nrf70_sys::MFP_OPTIONAL,
                Mfp::Required => nrf70_sys::MFP_REQUIRED,
            },
            credential_kind,
            credential_len,
            credential,
        });
        credential.zeroize();
        let mut g = self.guard(true)?;
        // Credentials go through the stash, never the command channel, so no
        // bitwise copy of the secret is left in the channel's queue storage.
        // Overwriting a stale entry drops it in place, which zeroizes it.
        self.r
            .connect_stash
            .lock(|stash| *stash.borrow_mut() = Some(target));
        self.r.commands.send(Command::Connect { id: g.id }).await;
        let result = self.done(&g).await;
        g.armed = false;
        result
    }
    pub async fn disconnect(&self, reason: u16) -> Result<(), Error> {
        self.simple(|id| Command::Disconnect { id, reason }).await
    }
    pub async fn set_power_save(&self, enabled: bool) -> Result<(), Error> {
        self.simple(|id| Command::SetPowerSave { id, enabled })
            .await
    }
    pub async fn reset(&self) -> Result<(), Error> {
        self.simple(|id| Command::Reset { id }).await
    }
    pub async fn shutdown(&self) -> Result<(), Error> {
        self.simple(|id| Command::Shutdown { id }).await
    }
    pub async fn stats(&self) -> Result<Stats, Error> {
        let g = self.guard(false)?;
        self.r.commands.send(Command::Stats { id: g.id }).await;
        match self.response(g.id).await {
            Response::Stats { stats, .. } => Ok(stats),
            _ => Err(Error::Fatal),
        }
    }
    pub async fn next_link_event(&self) -> LinkEvent {
        self.r.events.receive().await
    }
}

impl<B: Bus + Send + 'static, const N: usize> Runner<'_, B, N> {
    pub async fn run(mut self) -> ! {
        loop {
            self.handle_cancel();
            if let Ok(cmd) = self.r.commands.try_receive() {
                self.command(cmd)
            }
            let _ = self.r.wake.try_take();
            if self.r.irq.try_take().is_some() {
                unsafe { nrf70_sys::notify_host_irq() }
            }
            if self.initialized && unsafe { nrf70_sys::host_irq_active() } {
                unsafe { nrf70_sys::notify_host_irq() }
            }
            let _ = unsafe { nrf70_sys::process(EVENT_DRAIN_BUDGET) };
            self.drain_events();
            self.check_connect_timeout();
            self.pump_rx();
            self.pump_tx();
            Timer::after(Duration::from_millis(1)).await;
        }
    }
    fn emit(&self, e: LinkEvent) {
        if self.r.events.try_send(e).is_err() {
            self.r.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn terminal(&self, mut response: Response) {
        while let Err(embassy_sync::channel::TrySendError::Full(returned)) =
            self.r.responses.try_send(response)
        {
            response = returned;
            if self.r.responses.try_receive().is_ok() {
                self.r.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    fn handle_cancel(&mut self) {
        let id = self.r.cancel_id.swap(0, Ordering::AcqRel);
        if id == 0 {
            return;
        }
        if self.scan_id == Some(id) {
            let _ = unsafe { nrf70_sys::scan_cancel() };
        }
        if self.connect_id == Some(id) {
            let _ = unsafe { nrf70_sys::connect_abort(3) };
            self.connect_id = None;
            self.clear_session();
            self.set_link(false, 0, 0);
            self.terminal(Response::Done {
                id,
                result: Err(Error::Cancelled),
            })
        }
    }
    /// Forgets all supplicant-session state; keys and the PMK live C-side and
    /// are torn down by the facade itself.
    fn clear_session(&mut self) {
        self.secured = false;
        self.port_authorized = false;
        self.session_established = false;
        self.pending_link = None;
    }
    /// Zeroizes and clears any pending connect credentials in place; nothing
    /// is moved out of the stash slot, so no bitwise residue is left behind.
    fn scrub_connect_stash(&self) {
        self.r.connect_stash.lock(|stash| {
            let mut slot = stash.borrow_mut();
            if let Some(params) = slot.as_mut() {
                params.0.credential.zeroize();
                params.0.credential_len = 0;
            }
            *slot = None;
        })
    }
    fn command(&mut self, cmd: Command) {
        match cmd {
            Command::Initialize { id, mac, country } => self.cmd_initialize(id, mac, country),
            Command::SetCountry { id, country } => self.cmd_set_country(id, country),
            Command::Scan { id, request } => self.cmd_scan(id, request),
            Command::Connect { id } => self.cmd_connect(id),
            Command::Disconnect { id, reason } => self.cmd_disconnect(id, reason),
            Command::SetPowerSave { id, enabled } => self.cmd_set_power_save(id, enabled),
            Command::Reset { id } => self.cmd_reset(id),
            Command::Shutdown { id } => self.cmd_shutdown(id),
            Command::Stats { id } => self.cmd_stats(id),
        }
    }
    fn cmd_initialize(&mut self, id: u32, mac: [u8; 6], country: Country) {
        let result = if self.initialized {
            Err(Error::Busy)
        } else {
            unsafe { nrf70_sys::init(self.platform, mac, country.bytes()) }.map_err(Error::from)
        };
        if result.is_ok() {
            self.initialized = true;
            self.mac = mac;
            self.country = Some(country);
            let s = unsafe { nrf70_sys::stats() };
            self.generation = s.generation;
            if let Some(net) = &mut self.net {
                net.set_hardware_address(HardwareAddress::Ethernet(mac));
                net.set_link_state(LinkState::Down)
            }
        }
        self.terminal(Response::Done { id, result })
    }
    fn cmd_set_country(&mut self, id: u32, country: Country) {
        let result = if self.scan_id.is_some() || self.connect_id.is_some() {
            Err(Error::Busy)
        } else {
            unsafe { nrf70_sys::set_country(country.bytes()) }.map_err(Error::from)
        };
        if result.is_ok() {
            self.country = Some(country)
        }
        self.fatal_if_needed(&result);
        self.terminal(Response::Done { id, result })
    }
    fn cmd_scan(&mut self, id: u32, request: ScanRequest) {
        if self.scan_id.is_some() {
            self.terminal(Response::ScanDone {
                id,
                result: Err(Error::Busy),
            })
        } else {
            let result = self.start_scan(request);
            if result.is_ok() {
                self.scan_id = Some(id)
            } else {
                self.terminal(Response::ScanDone { id, result })
            }
        }
    }
    fn cmd_connect(&mut self, id: u32) {
        if self.connect_id.is_some() || self.scan_id.is_some() {
            self.scrub_connect_stash();
            self.terminal(Response::Done {
                id,
                result: Err(Error::Busy),
            })
        } else {
            // Start from the stash in place: the credential bytes are
            // never moved out of the static slot, and are zeroized
            // there before the slot is cleared.
            let outcome = self.r.connect_stash.lock(|stash| {
                let mut slot = stash.borrow_mut();
                let outcome = match slot.as_mut() {
                    None => Err(Error::InvalidRequest),
                    Some(params) => {
                        let secured = params.0.security != nrf70_sys::Security::Open;
                        let result = unsafe { nrf70_sys::connect_start(&params.0) }
                            .map(|_| secured)
                            .map_err(Error::from);
                        params.0.credential.zeroize();
                        params.0.credential_len = 0;
                        result
                    }
                };
                // Drops in place; the credential is already zeroized.
                *slot = None;
                outcome
            });
            match outcome {
                Ok(secured) => {
                    self.connect_id = Some(id);
                    self.clear_session();
                    self.secured = secured;
                    self.connect_deadline = self.platform_time().wrapping_add(if secured {
                        SECURE_CONNECT_TIMEOUT_US
                    } else {
                        OPEN_CONNECT_TIMEOUT_US
                    })
                }
                Err(error) => self.terminal(Response::Done {
                    id,
                    result: Err(error),
                }),
            }
        }
    }
    fn cmd_disconnect(&mut self, id: u32, reason: u16) {
        let result = unsafe { nrf70_sys::disconnect(reason) }.map_err(Error::from);
        self.terminal(Response::Done { id, result })
    }
    fn cmd_set_power_save(&mut self, id: u32, enabled: bool) {
        self.terminal(Response::Done {
            id,
            result: unsafe { nrf70_sys::set_power_save(enabled) }.map_err(Error::from),
        })
    }
    fn cmd_reset(&mut self, id: u32) {
        let result = self.reset_driver();
        self.terminal(Response::Done { id, result })
    }
    fn cmd_shutdown(&mut self, id: u32) {
        let result = if self.initialized {
            unsafe { nrf70_sys::deinit() }.map_err(Error::from)
        } else {
            Err(Error::NotInitialized)
        };
        self.initialized = false;
        self.fail_operations(Error::Cancelled);
        self.clear_session();
        self.set_link(false, 0, 0);
        self.terminal(Response::Done { id, result })
    }
    fn cmd_stats(&mut self, id: u32) {
        let mut c = unsafe { nrf70_sys::stats() };
        c.arena_used = self.platform.arena().used();
        c.arena_high_water = self.platform.arena().high_water();
        self.terminal(Response::Stats {
            id,
            stats: Stats {
                c,
                dropped_results: self.r.dropped.load(Ordering::Relaxed),
                stale_events: self.r.stale.load(Ordering::Relaxed),
                tx_channel_drops: self.r.tx_drops.load(Ordering::Relaxed),
                connect_timeouts: self.r.timeouts.load(Ordering::Relaxed),
            },
        })
    }
    fn platform_time(&self) -> u32 {
        self.platform.now_us_for_runner()
    }
    fn start_scan(&mut self, q: ScanRequest) -> Result<(), Error> {
        if !self.initialized {
            return Err(Error::NotInitialized);
        }
        if q.max_results as usize > MAX_SCAN_RESULTS {
            return Err(Error::InvalidRequest);
        }
        unsafe { nrf70_sys::set_country(q.country.bytes()) }.map_err(Error::from)?;
        let mut r = nrf70_sys::ScanRequest {
            passive: q.passive,
            channel_count: q.channels.len() as u8,
            ssid_len: q.ssid_filter.len() as u8,
            dwell_active_ms: q.dwell_active_ms,
            dwell_passive_ms: q.dwell_passive_ms,
            max_results: q.max_results,
            ..Default::default()
        };
        r.ssid[..q.ssid_filter.len()].copy_from_slice(&q.ssid_filter);
        for (i, c) in q.channels.iter().enumerate() {
            r.channels[i] = nrf70_sys::Channel {
                band: 1,
                channel: *c,
            }
        }
        unsafe { nrf70_sys::scan_start(&r) }.map_err(Error::from)
    }
    fn drain_events(&mut self) {
        while let Some(event) = unsafe { nrf70_sys::event_pop() } {
            let event_generation = match event {
                nrf70_sys::Event::ScanResult { generation, .. }
                | nrf70_sys::Event::ScanComplete { generation, .. }
                | nrf70_sys::Event::Auth { generation, .. }
                | nrf70_sys::Event::Assoc { generation, .. }
                | nrf70_sys::Event::Disconnected { generation, .. }
                | nrf70_sys::Event::Link { generation, .. }
                | nrf70_sys::Event::TxComplete { generation, .. }
                | nrf70_sys::Event::RxReady { generation }
                | nrf70_sys::Event::FirmwareRestart { generation }
                | nrf70_sys::Event::PortAuthorized { generation }
                | nrf70_sys::Event::HandshakeFailed { generation, .. }
                | nrf70_sys::Event::Fatal { generation, .. } => generation,
            };
            if event_generation != self.generation {
                self.r.stale.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            match event {
                nrf70_sys::Event::ScanResult { result, .. } => self.on_scan_result(result),
                nrf70_sys::Event::ScanComplete { status, .. } => {
                    #[cfg(feature = "defmt")]
                    if status != 0 {
                        defmt::warn!("nrf70: scan failed (status {=i32})", status);
                    }
                    if let Some(id) = self.scan_id.take() {
                        self.terminal(Response::ScanDone {
                            id,
                            result: status_result(status),
                        })
                    }
                }
                nrf70_sys::Event::Auth { status, .. } | nrf70_sys::Event::Assoc { status, .. } => {
                    #[cfg(feature = "defmt")]
                    if status != 0 {
                        defmt::warn!(
                            "nrf70: auth/assoc rejected or timed out (status {=i32})",
                            status
                        );
                    }
                    // The facade drives auth -> assoc itself; only failures matter here.
                    if status != 0
                        && let Some(id) = self.connect_id.take()
                    {
                        self.clear_session();
                        self.terminal(Response::Done {
                            id,
                            result: Err(Error::Io),
                        })
                    }
                }
                nrf70_sys::Event::Link {
                    up,
                    frequency_mhz,
                    rssi_dbm,
                    ..
                } => self.on_link(up, frequency_mhz, rssi_dbm),
                nrf70_sys::Event::PortAuthorized { .. } => self.on_port_authorized(),
                nrf70_sys::Event::HandshakeFailed { reason_code, .. } => {
                    self.on_handshake_failed(reason_code)
                }
                nrf70_sys::Event::Disconnected { reason_code, .. } => {
                    self.on_disconnected(reason_code)
                }
                nrf70_sys::Event::TxComplete { status, .. } => {
                    if status != 0 {
                        self.r.tx_drops.fetch_add(1, Ordering::Relaxed);
                    }
                }
                nrf70_sys::Event::RxReady { .. } => {}
                nrf70_sys::Event::FirmwareRestart { generation } => {
                    self.emit(LinkEvent::FirmwareRestart { generation });
                    self.clear_session();
                    self.set_link(false, 0, 0)
                }
                nrf70_sys::Event::Fatal { .. } => self.on_fatal(),
            }
        }
    }
    fn on_scan_result(&mut self, result: nrf70_sys::ScanResult) {
        if let Some(id) = self.scan_id {
            let mut ssid = Vec::new();
            let _ = ssid.extend_from_slice(&result.ssid[..result.ssid_len.min(32) as usize]);
            let ap = AccessPoint {
                ssid,
                channel: result.channel,
                rssi_dbm: result.rssi_dbm,
                bssid: result.bssid,
                security: match result.security {
                    nrf70_sys::Security::Open => Security::Open,
                    nrf70_sys::Security::Wpa2Psk => Security::Wpa2Personal,
                    nrf70_sys::Security::Wpa2PskSha256 => Security::Wpa2Sha256,
                    nrf70_sys::Security::Wpa3Sae => Security::Wpa3Sae,
                    nrf70_sys::Security::Other => Security::Other,
                },
                mfp: result.mfp,
            };
            if self
                .r
                .responses
                .try_send(Response::Result { id, ap })
                .is_err()
            {
                self.r.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    fn on_link(&mut self, up: bool, frequency_mhz: u16, rssi_dbm: i8) {
        if up && self.connect_id.is_none() && !self.session_established {
            // Stale carrier-up: no connect is pending and no
            // session was ever established (e.g. assoc completed
            // just before an abort's deauth reached the firmware).
            // Raising the link here would open the data path with
            // no keys installed, so force the firmware link back
            // down instead and never surface the event.
            self.r.stale.fetch_add(1, Ordering::Relaxed);
            let _ = unsafe { nrf70_sys::disconnect(3) };
        } else if up && self.secured && !self.port_authorized {
            // Secured sessions are not usable until PORT_AUTHORIZED;
            // hold the net link down and remember the radio numbers.
            self.pending_link = Some((frequency_mhz, rssi_dbm));
        } else {
            self.set_link(up, frequency_mhz, rssi_dbm);
            if up && let Some(id) = self.connect_id.take() {
                self.session_established = true;
                self.terminal(Response::Done { id, result: Ok(()) })
            }
        }
    }
    fn on_port_authorized(&mut self) {
        self.port_authorized = true;
        self.session_established = true;
        let (frequency_mhz, rssi_dbm) = self.pending_link.take().unwrap_or((0, 0));
        self.set_link(true, frequency_mhz, rssi_dbm);
        if let Some(id) = self.connect_id.take() {
            self.terminal(Response::Done { id, result: Ok(()) })
        }
    }
    fn on_handshake_failed(&mut self, reason_code: u16) {
        self.last_reason = reason_code;
        self.clear_session();
        if self.linked {
            self.set_link(false, 0, 0);
        } else {
            // The net link never rose (the Link-up was parked
            // during the handshake), so set_link would emit
            // nothing; report the 802.11 reason code directly.
            self.emit(LinkEvent::Down { reason_code });
        }
        if let Some(id) = self.connect_id.take() {
            self.terminal(Response::Done {
                id,
                result: Err(Error::HandshakeFailed),
            })
        }
    }
    fn on_disconnected(&mut self, reason_code: u16) {
        self.last_reason = reason_code;
        self.clear_session();
        if self.linked {
            self.set_link(false, 0, 0);
        } else if self.connect_id.is_some() {
            // A connect failed before the net link ever rose;
            // surface the reason code that set_link would swallow.
            self.emit(LinkEvent::Down { reason_code });
        }
        if let Some(id) = self.connect_id.take() {
            self.terminal(Response::Done {
                id,
                result: Err(Error::Io),
            })
        }
    }
    fn on_fatal(&mut self) {
        self.emit(LinkEvent::Fatal);
        self.fail_operations(Error::Fatal);
        if self.initialized {
            let _ = unsafe { nrf70_sys::deinit() };
            self.initialized = false
        }
        self.clear_session();
        self.set_link(false, 0, 0)
    }
    fn set_link(&mut self, up: bool, frequency: u16, rssi: i8) {
        if self.linked == up && (!up || frequency == 0) {
            return;
        }
        self.linked = up;
        if let Some(net) = &mut self.net {
            net.set_link_state(if up { LinkState::Up } else { LinkState::Down })
        }
        self.emit(if up {
            LinkEvent::Up {
                frequency_mhz: frequency,
                rssi_dbm: rssi,
            }
        } else {
            LinkEvent::Down {
                reason_code: self.last_reason,
            }
        })
    }
    fn check_connect_timeout(&mut self) {
        if let Some(id) = self.connect_id
            && self.platform_time().wrapping_sub(self.connect_deadline) as i32 >= 0
        {
            self.connect_id = None;
            self.r.timeouts.fetch_add(1, Ordering::Relaxed);
            let _ = unsafe { nrf70_sys::connect_abort(3) };
            self.clear_session();
            self.set_link(false, 0, 0);
            self.terminal(Response::Done {
                id,
                result: Err(Error::Timeout),
            })
        }
    }
    fn pump_rx(&mut self) {
        let Some(net) = &mut self.net else { return };
        loop {
            let Some(dst) = net.try_rx_buf() else { return };
            let mut frame = [0u8; ETHERNET_FRAME_SIZE];
            match unsafe { nrf70_sys::rx_pop(&mut frame) } {
                Ok(Some(meta)) => {
                    let n = meta.length as usize;
                    if !(14..=ETHERNET_FRAME_SIZE).contains(&n) {
                        continue;
                    }
                    // EAPOL frames belong to the C-side supplicant; the facade
                    // never queues them here, but skip any defensively so key
                    // material can never reach embassy-net.
                    if frame[12..14] == EAPOL_ETHERTYPE {
                        continue;
                    }
                    dst[..n].copy_from_slice(&frame[..n]);
                    net.rx_done(n)
                }
                Ok(None) => return,
                Err(_) => return,
            }
        }
    }
    fn pump_tx(&mut self) {
        // For secured sessions the net link only rises on PORT_AUTHORIZED, but
        // keep the port check as a second gate against ever transmitting data
        // frames during the handshake.
        if !self.linked || (self.secured && !self.port_authorized) {
            return;
        }
        let Some(net) = &mut self.net else { return };
        let Some(frame) = net.try_tx_buf() else {
            return;
        };
        let token = self.next_tx_token;
        match unsafe { nrf70_sys::tx(token, frame) } {
            Ok(()) => {
                self.next_tx_token = self.next_tx_token.wrapping_add(1).max(1);
                net.tx_done()
            }
            Err(nrf70_sys::Status::QueueFull) => {}
            Err(_) => {
                self.r.tx_drops.fetch_add(1, Ordering::Relaxed);
                net.tx_done()
            }
        }
    }
    fn reset_driver(&mut self) -> Result<(), Error> {
        if !self.initialized {
            return Err(Error::NotInitialized);
        }
        let country = self.country.ok_or(Error::InvalidCountry)?;
        self.fail_operations(Error::Cancelled);
        self.clear_session();
        self.set_link(false, 0, 0);
        self.flush_tx();
        unsafe { nrf70_sys::reset(self.mac, country.bytes()) }.map_err(Error::from)?;
        self.generation = unsafe { nrf70_sys::stats() }.generation;
        Ok(())
    }
    fn flush_tx(&mut self) {
        if let Some(net) = &mut self.net {
            while net.try_tx_buf().is_some() {
                net.tx_done();
                self.r.tx_drops.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    fn fail_operations(&mut self, error: Error) {
        if let Some(id) = self.scan_id.take() {
            self.terminal(Response::ScanDone {
                id,
                result: Err(error),
            })
        }
        if let Some(id) = self.connect_id.take() {
            self.clear_session();
            self.terminal(Response::Done {
                id,
                result: Err(error),
            })
        }
    }
    fn fatal_if_needed(&mut self, result: &Result<(), Error>) {
        if *result == Err(Error::Fatal) {
            self.fail_operations(Error::Fatal);
            let _ = unsafe { nrf70_sys::deinit() };
            self.initialized = false;
            self.set_link(false, 0, 0)
        }
    }
}
// This is only a display-scan prefilter. A WPA3 label may include WPA2 PSK
// transition mode; the C connect scan validates the actual RSN AKMs/ciphers.
fn credential_candidate(security: Security, credential: &Credential) -> bool {
    matches!(
        (security, credential),
        (Security::Open, Credential::Open)
            | (
                Security::Wpa2Personal | Security::Wpa2Sha256 | Security::Wpa3Sae,
                Credential::Passphrase(_) | Credential::Psk(_),
            )
    )
}
fn status_result(status: i32) -> Result<(), Error> {
    match status {
        0 => Ok(()),
        -6 => Err(Error::Cancelled),
        _ => Err(Error::Io),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_scan_allows_transition_candidates_but_not_open_downgrades() {
        let psk = Credential::Psk([0; 32]);
        assert!(credential_candidate(Security::Wpa3Sae, &psk));
        assert!(credential_candidate(Security::Wpa2Personal, &psk));
        assert!(credential_candidate(Security::Wpa2Sha256, &psk));
        assert!(!credential_candidate(Security::Open, &psk));
        assert!(!credential_candidate(Security::Other, &psk));
        assert!(credential_candidate(Security::Open, &Credential::Open));
        assert!(!credential_candidate(Security::Wpa3Sae, &Credential::Open));
        assert!(!credential_candidate(
            Security::Wpa2Personal,
            &Credential::Open
        ));
    }
}
