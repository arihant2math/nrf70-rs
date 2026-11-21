#![no_std]
#![allow(clippy::missing_safety_doc)]

mod raw {
    #![allow(
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals,
        dead_code
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use core::{
    cell::UnsafeCell,
    ffi::{c_char, c_void},
    mem::{align_of, size_of},
    slice,
};

pub const MAX_CHANNELS: usize = raw::NRF70_FACADE_MAX_CHANNELS as usize;
pub const MAX_SSID_LEN: usize = raw::NRF70_FACADE_MAX_SSID_LEN as usize;
pub const MAX_FRAME_LEN: usize = raw::NRF70_FACADE_MAX_FRAME_LEN as usize;
pub const MAX_KEY_LEN: usize = raw::NRF70_FACADE_MAX_KEY_LEN as usize;
pub const MAX_SEQ_LEN: usize = raw::NRF70_FACADE_MAX_SEQ_LEN as usize;
pub const MAX_CREDENTIAL_LEN: usize = raw::NRF70_FACADE_MAX_CREDENTIAL_LEN as usize;
/// Values for [`ConnectTarget::credential_kind`].
pub const CREDENTIAL_NONE: u8 =
    raw::nrf70_facade_credential_kind_NRF70_FACADE_CREDENTIAL_NONE as u8;
pub const CREDENTIAL_PASSPHRASE: u8 =
    raw::nrf70_facade_credential_kind_NRF70_FACADE_CREDENTIAL_PASSPHRASE as u8;
pub const CREDENTIAL_PSK: u8 = raw::nrf70_facade_credential_kind_NRF70_FACADE_CREDENTIAL_PSK as u8;
/// Values for [`ConnectTarget::mfp`].
pub const MFP_DISABLED: u8 = raw::nrf70_facade_mfp_NRF70_FACADE_MFP_DISABLED as u8;
pub const MFP_OPTIONAL: u8 = raw::nrf70_facade_mfp_NRF70_FACADE_MFP_OPTIONAL as u8;
pub const MFP_REQUIRED: u8 = raw::nrf70_facade_mfp_NRF70_FACADE_MFP_REQUIRED_ as u8;
pub const COEX_SR_BLE: u8 = raw::nrf70_facade_coex_sr_protocol_NRF70_FACADE_COEX_SR_BLE as u8;
pub const COEX_SR_IEEE802154: u8 =
    raw::nrf70_facade_coex_sr_protocol_NRF70_FACADE_COEX_SR_IEEE802154 as u8;

/// Asserts each bindgen struct's size (and `align`) at compile time, and
/// `abi_ok` checks them against the C side's `sizeof` (and `alignof` with
/// `probe`).
macro_rules! abi_checks {
    ($($ty:ident, $size:expr, $sizeof:ident $(, align $align:expr)? $(, probe $alignof:ident)?;)*) => {
        $(
            const _: () = assert!(size_of::<raw::$ty>() == $size);
            $(const _: () = assert!(align_of::<raw::$ty>() == $align);)?
        )*
        unsafe fn abi_ok() -> bool {
            true
            $(
                && unsafe { raw::$sizeof() } as usize == size_of::<raw::$ty>()
                $(&& unsafe { raw::$alignof() } as usize == align_of::<raw::$ty>())?
            )*
        }
    };
}
abi_checks! {
    nrf70_facade_scan_request, 106, nrf70_facade_sizeof_scan_request, align 2, probe nrf70_facade_alignof_scan_request;
    nrf70_facade_scan_result, 44, nrf70_facade_sizeof_scan_result;
    nrf70_facade_connect_request, 110, nrf70_facade_sizeof_connect_request, align 2;
    nrf70_facade_key, 96, nrf70_facade_sizeof_key;
    nrf70_facade_event, 64, nrf70_facade_sizeof_event;
    nrf70_facade_link_info, 48, nrf70_facade_sizeof_link_info;
    nrf70_facade_rx_meta, 12, nrf70_facade_sizeof_rx_meta;
    nrf70_facade_stats, 156, nrf70_facade_sizeof_stats;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, num_enum::FromPrimitive)]
#[repr(i32)]
pub enum Status {
    Invalid = -1,
    Busy = -2,
    Io = -3,
    NoMemory = -4,
    NotInitialized = -5,
    Cancelled = -6,
    #[num_enum(default)]
    Fatal = -7,
    QueueFull = -8,
    NotConnected = -9,
}

#[derive(Clone, Copy, Default)]
pub struct Channel {
    pub band: u8,
    pub channel: u8,
}
#[derive(Clone, Copy)]
pub struct ScanRequest {
    pub passive: bool,
    pub channel_count: u8,
    pub ssid_len: u8,
    pub dwell_active_ms: u16,
    pub dwell_passive_ms: u16,
    pub max_results: u16,
    pub ssid: [u8; MAX_SSID_LEN],
    pub channels: [Channel; MAX_CHANNELS],
}
impl Default for ScanRequest {
    fn default() -> Self {
        Self {
            passive: false,
            channel_count: 0,
            ssid_len: 0,
            dwell_active_ms: 50,
            dwell_passive_ms: 130,
            max_results: 0,
            ssid: [0; MAX_SSID_LEN],
            channels: [Channel::default(); MAX_CHANNELS],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Security {
    Open,
    Wpa2Psk,
    Wpa2PskSha256,
    Wpa3Sae,
    Other,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanResult {
    pub ssid: [u8; MAX_SSID_LEN],
    pub ssid_len: u8,
    pub channel: u8,
    pub band: u8,
    pub rssi_dbm: i8,
    pub bssid: [u8; 6],
    pub security: Security,
    pub mfp: u8,
}
/// The association the last link-up announced. `rssi_dbm` and `tx_rate_kbps`
/// are the RPU's latest [`Event::LinkInfo`] reply for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkInfo {
    pub ssid: [u8; MAX_SSID_LEN],
    pub ssid_len: u8,
    pub bssid: [u8; 6],
    pub frequency_mhz: u16,
    /// As negotiated.
    pub security: Security,
    /// Whether management frames are protected.
    pub mfp: bool,
    /// Beacon average, else the last frame received.
    pub rssi_dbm: Option<i8>,
    pub tx_rate_kbps: Option<u32>,
}
/// Carries credential bytes, so no `Debug`/`Copy`/`Clone`; the caller zeroizes
/// its copy after `connect_start` returns.
pub struct ConnectTarget {
    pub ssid: [u8; MAX_SSID_LEN],
    pub ssid_len: u8,
    pub bssid: [u8; 6],
    pub frequency_mhz: u16,
    pub security: Security,
    pub mfp: u8,
    pub credential_kind: u8,
    pub credential_len: u8,
    pub credential: [u8; MAX_CREDENTIAL_LEN],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyType {
    Group,
    Pairwise,
    Peer,
}
#[derive(Clone, Copy)]
pub struct Key {
    pub key_type: KeyType,
    pub key_index: u8,
    pub cipher_suite: u32,
    pub peer: [u8; 6],
    pub key: [u8; MAX_KEY_LEN],
    pub key_len: u8,
    pub sequence: [u8; MAX_SEQ_LEN],
    pub sequence_len: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    ScanResult {
        generation: u32,
        result: ScanResult,
    },
    ScanComplete {
        generation: u32,
        status: i32,
    },
    Auth {
        generation: u32,
        status: i32,
        frequency_mhz: u16,
    },
    Assoc {
        generation: u32,
        status: i32,
        frequency_mhz: u16,
    },
    Disconnected {
        generation: u32,
        reason_code: u16,
    },
    Link {
        generation: u32,
        up: bool,
        frequency_mhz: u16,
        rssi_dbm: i8,
    },
    TxComplete {
        generation: u32,
        token: u32,
        status: i32,
    },
    RxReady {
        generation: u32,
    },
    FirmwareRestart {
        generation: u32,
    },
    /// The 4-way handshake finished and the controlled port is authorized.
    PortAuthorized {
        generation: u32,
    },
    /// The supplicant gave up: `status` is a facade status, `reason_code` an 802.11 reason.
    HandshakeFailed {
        generation: u32,
        status: i32,
        reason_code: u16,
    },
    /// The RPU answered [`link_info_request`]; with a zero `status`,
    /// [`link_info`] holds its reply.
    LinkInfo {
        generation: u32,
        status: i32,
    },
    Fatal {
        generation: u32,
        reason: i32,
    },
}
#[derive(Clone, Copy, Debug, Default)]
pub struct RxMeta {
    pub generation: u32,
    pub length: u16,
    pub rssi_dbm: i8,
}
/// Field names must match `struct nrf70_facade_stats`; all counters are `u32`.
macro_rules! stats_fields {
    ($($field:ident,)*) => {
        #[derive(Clone, Copy, Debug, Default)]
        pub struct Stats {
            $(pub $field: u32,)*
        }
        /// # Safety Call only from the serialized runner.
        pub unsafe fn stats() -> Stats {
            let mut s = raw::nrf70_facade_stats::default();
            unsafe { raw::nrf70_facade_stats_get(&mut s) };
            Stats {
                $($field: s.$field,)*
            }
        }
    };
}
stats_fields! {
    generation,
    scans_started,
    scans_completed,
    scans_cancelled,
    dropped_events,
    allocation_failures,
    spi_errors,
    fatal_errors,
    max_c_call_us,
    max_spi_transfer_us,
    max_osal_delay_us,
    arena_used,
    arena_high_water,
    tx_submitted,
    tx_completed,
    tx_failed,
    tx_queue_full,
    rx_received,
    rx_delivered,
    rx_dropped,
    rx_invalid,
    link_ups,
    link_downs,
    disconnects,
    firmware_restarts,
    resets,
    tx_copies,
    rx_copies,
    rx_queue_high_water,
    nbuf_in_use,
    nbuf_high_water,
    eapol_rx,
    eapol_rx_dropped,
    eapol_tx,
    eapol_tx_failed,
    handshakes_completed,
    handshake_failures,
    rekeys,
    rx_dropped_unauthorized,
}

/// Contract implemented by the safe crate's single, thread-mode platform owner.
/// Implementations must not call back into this crate from any method.
///
/// # Safety
/// The implementation must remain alive while installed, serialize mutable hardware access,
/// and return allocations valid until the matching `free`.
pub unsafe trait Platform: Sync {
    unsafe fn alloc(&self, size: u32, align: u32, zeroed: bool) -> *mut u8;
    unsafe fn free(&self, ptr: *mut u8);
    fn power_on(&self) -> i32;
    fn power_off(&self);
    fn bus_init(&self) -> i32;
    fn bus_deinit(&self);
    fn read_reg32(&self, address: u32, value: &mut u32) -> i32;
    fn write_reg32(&self, address: u32, value: u32) -> i32;
    fn read(&self, address: u32, dst: &mut [u8]) -> i32;
    fn write(&self, address: u32, src: &[u8]) -> i32;
    fn sleep(&self) -> i32;
    fn wake(&self) -> i32;
    fn power_status(&self) -> i32;
    fn delay_us(&self, us: u32);
    fn now_us(&self) -> u32;
    fn random_u8(&self) -> u8;
    fn host_irq_active(&self) -> bool;
    /// # Safety
    /// `message` must be null or point to a valid, nul-terminated string for
    /// the duration of this call.
    unsafe fn log(&self, _level: u8, _message: *const c_char) {}
    /// # Safety
    /// `message` must be null or point to a valid, nul-terminated string for
    /// the duration of this call.
    unsafe fn fatal(&self, _reason: i32, _message: *const c_char) {}
}
struct Slot(UnsafeCell<Option<&'static dyn Platform>>);
unsafe impl Sync for Slot {}
static PLATFORM: Slot = Slot(UnsafeCell::new(None));
fn platform() -> &'static dyn Platform {
    unsafe { (*PLATFORM.0.get()).expect("nrf70 platform not installed") }
}
unsafe extern "C" fn alloc(_: *mut c_void, s: u32, a: u32, z: u8) -> *mut c_void {
    unsafe { platform().alloc(s, a, z != 0) }.cast()
}
unsafe extern "C" fn free(_: *mut c_void, p: *mut c_void) {
    unsafe { platform().free(p.cast()) }
}
unsafe extern "C" fn power_on(_: *mut c_void) -> i32 {
    platform().power_on()
}
unsafe extern "C" fn power_off(_: *mut c_void) {
    platform().power_off()
}
unsafe extern "C" fn bus_init(_: *mut c_void) -> i32 {
    platform().bus_init()
}
unsafe extern "C" fn bus_deinit(_: *mut c_void) {
    platform().bus_deinit()
}
unsafe extern "C" fn read_reg(_: *mut c_void, a: u32, v: *mut u32) -> i32 {
    platform().read_reg32(a, unsafe { &mut *v })
}
unsafe extern "C" fn write_reg(_: *mut c_void, a: u32, v: u32) -> i32 {
    platform().write_reg32(a, v)
}
unsafe extern "C" fn read(_: *mut c_void, a: u32, p: *mut u8, n: u32) -> i32 {
    platform().read(a, unsafe { slice::from_raw_parts_mut(p, n as usize) })
}
unsafe extern "C" fn write(_: *mut c_void, a: u32, p: *const u8, n: u32) -> i32 {
    platform().write(a, unsafe { slice::from_raw_parts(p, n as usize) })
}
unsafe extern "C" fn sleep(_: *mut c_void) -> i32 {
    platform().sleep()
}
unsafe extern "C" fn wake(_: *mut c_void) -> i32 {
    platform().wake()
}
unsafe extern "C" fn ps(_: *mut c_void) -> i32 {
    platform().power_status()
}
unsafe extern "C" fn delay(_: *mut c_void, u: u32) {
    platform().delay_us(u)
}
unsafe extern "C" fn now(_: *mut c_void) -> u32 {
    platform().now_us()
}
unsafe extern "C" fn random(_: *mut c_void) -> u8 {
    platform().random_u8()
}
unsafe extern "C" fn irq(_: *mut c_void) -> u8 {
    platform().host_irq_active() as u8
}
unsafe extern "C" fn log(_: *mut c_void, l: u8, m: *const c_char) {
    // SAFETY: the facade owns `m` and guarantees a valid C string for this call.
    unsafe { platform().log(l, m) }
}
unsafe extern "C" fn fatal(_: *mut c_void, r: i32, m: *const c_char) {
    // SAFETY: the facade owns `m` and guarantees a valid C string for this call.
    unsafe { platform().fatal(r, m) }
}
struct Ops(raw::nrf70_facade_platform_ops);
unsafe impl Sync for Ops {}
static OPS: Ops = Ops(raw::nrf70_facade_platform_ops {
    abi_version: raw::NRF70_FACADE_ABI_VERSION,
    context: core::ptr::null_mut(),
    alloc: Some(alloc),
    free: Some(free),
    power_on: Some(power_on),
    power_off: Some(power_off),
    bus_init: Some(bus_init),
    bus_deinit: Some(bus_deinit),
    read_reg32: Some(read_reg),
    write_reg32: Some(write_reg),
    read: Some(read),
    write: Some(write),
    sleep: Some(sleep),
    wake: Some(wake),
    power_status: Some(ps),
    delay_us: Some(delay),
    now_us: Some(now),
    random_u8: Some(random),
    host_irq_active: Some(irq),
    log: Some(log),
    fatal: Some(fatal),
});

fn result(code: i32) -> Result<(), Status> {
    if code == 0 {
        Ok(())
    } else {
        Err(Status::from(code))
    }
}
/// # Safety No sys operation may execute concurrently; call only from the driver runner.
pub unsafe fn init(p: &'static dyn Platform, mac: [u8; 6], country: [u8; 2]) -> Result<(), Status> {
    if !unsafe { abi_ok() } {
        return Err(Status::Fatal);
    }
    unsafe { *PLATFORM.0.get() = Some(p) };
    let r = result(unsafe { raw::nrf70_facade_init(&OPS.0, mac.as_ptr(), country.as_ptr()) });
    if r.is_err() {
        unsafe { *PLATFORM.0.get() = None }
    }
    r
}
/// # Safety No sys operation may execute concurrently.
pub unsafe fn deinit() -> Result<(), Status> {
    let r = result(unsafe { raw::nrf70_facade_deinit() });
    unsafe { *PLATFORM.0.get() = None };
    r
}
/// # Safety Call only from the serialized runner.
pub unsafe fn reset(mac: [u8; 6], country: [u8; 2]) -> Result<(), Status> {
    result(unsafe { raw::nrf70_facade_reset(mac.as_ptr(), country.as_ptr()) })
}
/// # Safety Call only from the serialized runner.
pub unsafe fn set_country(c: [u8; 2]) -> Result<(), Status> {
    result(unsafe { raw::nrf70_facade_set_country(c.as_ptr()) })
}
/// # Safety Call only from the serialized runner.
pub unsafe fn scan_start(q: &ScanRequest) -> Result<(), Status> {
    let mut r = raw::nrf70_facade_scan_request {
        passive: q.passive as u8,
        channel_count: q.channel_count,
        ssid_len: q.ssid_len,
        dwell_active_ms: q.dwell_active_ms,
        dwell_passive_ms: q.dwell_passive_ms,
        max_results: q.max_results,
        ssid: q.ssid,
        ..Default::default()
    };
    for (r, q) in r.channels.iter_mut().zip(&q.channels) {
        r.band = q.band;
        r.channel = q.channel;
    }
    result(unsafe { raw::nrf70_facade_scan_start(&r) })
}
/// # Safety Call only from the serialized runner.
pub unsafe fn scan_cancel() -> Result<(), Status> {
    result(unsafe { raw::nrf70_facade_scan_cancel() })
}
/// Best-effort secret wipe: volatile byte stores the compiler may not elide.
fn wipe<T>(value: &mut T) {
    let p = (value as *mut T).cast::<u8>();
    for i in 0..size_of::<T>() {
        unsafe { core::ptr::write_volatile(p.add(i), 0) }
    }
}
fn security(raw: u8) -> Security {
    match raw as u32 {
        raw::nrf70_facade_security_NRF70_FACADE_SECURITY_OPEN => Security::Open,
        raw::nrf70_facade_security_NRF70_FACADE_SECURITY_WPA2_PSK => Security::Wpa2Psk,
        raw::nrf70_facade_security_NRF70_FACADE_SECURITY_WPA2_PSK_SHA256 => Security::Wpa2PskSha256,
        raw::nrf70_facade_security_NRF70_FACADE_SECURITY_WPA3_SAE => Security::Wpa3Sae,
        _ => Security::Other,
    }
}
fn raw_security(s: Security) -> u8 {
    (match s {
        Security::Open => raw::nrf70_facade_security_NRF70_FACADE_SECURITY_OPEN,
        Security::Wpa2Psk => raw::nrf70_facade_security_NRF70_FACADE_SECURITY_WPA2_PSK,
        Security::Wpa2PskSha256 => raw::nrf70_facade_security_NRF70_FACADE_SECURITY_WPA2_PSK_SHA256,
        Security::Wpa3Sae => raw::nrf70_facade_security_NRF70_FACADE_SECURITY_WPA3_SAE,
        Security::Other => raw::nrf70_facade_security_NRF70_FACADE_SECURITY_OTHER,
    }) as u8
}
/// The local raw copy of the credential is wiped before returning; the caller
/// zeroizes its own [`ConnectTarget`].
/// # Safety Call only from the serialized runner.
pub unsafe fn connect_start(t: &ConnectTarget) -> Result<(), Status> {
    let mut r = raw::nrf70_facade_connect_request {
        ssid_len: t.ssid_len,
        ssid: t.ssid,
        bssid: t.bssid,
        frequency_mhz: t.frequency_mhz,
        security: raw_security(t.security),
        mfp: t.mfp,
        credential_kind: t.credential_kind,
        credential_len: t.credential_len,
        credential: t.credential,
    };
    let code = unsafe { raw::nrf70_facade_connect_start(&r) };
    wipe(&mut r);
    result(code)
}
/// Also valid after a completed connect; deauthenticates if associated.
/// # Safety Call only from the serialized runner.
pub unsafe fn connect_abort(reason: u16) -> Result<(), Status> {
    result(unsafe { raw::nrf70_facade_connect_abort(reason) })
}
/// # Safety Call only from the serialized runner.
pub unsafe fn disconnect(reason: u16) -> Result<(), Status> {
    result(unsafe { raw::nrf70_facade_disconnect(reason) })
}
fn raw_key(k: &Key) -> raw::nrf70_facade_key {
    raw::nrf70_facade_key {
        key_type: (match k.key_type {
            KeyType::Group => raw::nrf70_facade_key_type_NRF70_FACADE_KEY_GROUP,
            KeyType::Pairwise => raw::nrf70_facade_key_type_NRF70_FACADE_KEY_PAIRWISE,
            KeyType::Peer => raw::nrf70_facade_key_type_NRF70_FACADE_KEY_PEER,
        }) as u8,
        key_index: k.key_index,
        key_len: k.key_len,
        seq_len: k.sequence_len,
        cipher_suite: k.cipher_suite,
        peer: k.peer,
        key: k.key,
        sequence: k.sequence,
    }
}
/// # Safety Call only from the serialized runner.
pub unsafe fn key_install(k: &Key) -> Result<(), Status> {
    result(unsafe { raw::nrf70_facade_key_install(&raw_key(k)) })
}
/// # Safety Call only from the serialized runner.
pub unsafe fn key_remove(k: &Key) -> Result<(), Status> {
    result(unsafe { raw::nrf70_facade_key_remove(&raw_key(k)) })
}
/// # Safety Call only from the serialized runner.
pub unsafe fn controlled_port(authorized: bool, peer: [u8; 6]) -> Result<(), Status> {
    result(unsafe { raw::nrf70_facade_controlled_port(authorized as u8, peer.as_ptr()) })
}
/// # Safety Call only from the serialized runner.
pub unsafe fn set_power_save(enabled: bool) -> Result<(), Status> {
    result(unsafe { raw::nrf70_facade_set_power_save(enabled as u8) })
}
/// Asks the RPU for the AP's station statistics; [`Event::LinkInfo`] follows.
/// # Safety Call only from the serialized runner.
pub unsafe fn link_info_request() -> Result<(), Status> {
    result(unsafe { raw::nrf70_facade_link_info_request() })
}
/// # Safety Call only from the serialized runner.
pub unsafe fn link_info() -> LinkInfo {
    let mut l = raw::nrf70_facade_link_info::default();
    unsafe { raw::nrf70_facade_link_info_get(&mut l) };
    LinkInfo {
        ssid: l.ssid,
        ssid_len: l.ssid_len,
        bssid: l.bssid,
        frequency_mhz: l.frequency_mhz,
        security: security(l.security),
        mfp: l.mfp != 0,
        rssi_dbm: (l.rssi_dbm != i8::MIN).then_some(l.rssi_dbm),
        tx_rate_kbps: (l.tx_rate_kbps != 0).then_some(l.tx_rate_kbps),
    }
}
/// # Safety Call only from the serialized runner.
pub unsafe fn coex_configure(sr_protocol: u8) -> Result<(), Status> {
    result(unsafe { raw::nrf70_facade_coex_configure(sr_protocol) })
}
/// # Safety Call only from the serialized runner.
pub unsafe fn coex_reset() -> Result<(), Status> {
    result(unsafe { raw::nrf70_facade_coex_reset() })
}
/// Copies `frame` into a C-owned nbuf before returning.
/// # Safety Call only from the serialized runner.
pub unsafe fn tx(token: u32, frame: &[u8]) -> Result<(), Status> {
    if frame.len() > MAX_FRAME_LEN {
        return Err(Status::Invalid);
    }
    result(unsafe { raw::nrf70_facade_tx(token, frame.as_ptr(), frame.len() as u16) })
}
/// # Safety Call only from the serialized runner.
pub unsafe fn rx_pop(frame: &mut [u8; MAX_FRAME_LEN]) -> Result<Option<RxMeta>, Status> {
    let mut m = raw::nrf70_facade_rx_meta::default();
    match unsafe { raw::nrf70_facade_rx_pop(frame.as_mut_ptr(), MAX_FRAME_LEN as u16, &mut m) } {
        0 => Ok(None),
        1 => Ok(Some(RxMeta {
            generation: m.generation,
            length: m.length,
            rssi_dbm: m.rssi_dbm,
        })),
        x => Err(Status::from(x)),
    }
}
/// # Safety Call only from thread mode in the serialized runner.
pub unsafe fn notify_host_irq() {
    unsafe { raw::nrf70_facade_notify_host_irq() }
}
/// # Safety Call only from the serialized runner.
pub unsafe fn process(budget: u32) -> u32 {
    unsafe { raw::nrf70_facade_process(budget) }
}
/// Microseconds until the facade next needs [`process`] or [`event_pop`]:
/// `Some(0)` when work is already waiting, `None` when only HOST_IRQ or
/// another call into this crate can create some.
/// # Safety Call only from the serialized runner.
pub unsafe fn next_deadline_us() -> Option<u32> {
    match unsafe { raw::nrf70_facade_next_deadline_us() } {
        raw::NRF70_FACADE_NO_DEADLINE => None,
        us => Some(us),
    }
}
/// # Safety Call only while the installed platform is alive.
pub unsafe fn host_irq_active() -> bool {
    unsafe { raw::nrf70_facade_host_irq_active() != 0 }
}
/// # Safety Call only from the serialized runner.
pub unsafe fn event_pop() -> Option<Event> {
    let mut e = raw::nrf70_facade_event::default();
    if unsafe { raw::nrf70_facade_event_pop(&mut e) } != 1 {
        return None;
    }
    let generation = e.generation;
    Some(match e.kind as u32 {
        raw::nrf70_facade_event_kind_NRF70_FACADE_EVENT_SCAN_RESULT => {
            let s = e.scan;
            Event::ScanResult {
                generation,
                result: ScanResult {
                    ssid: s.ssid,
                    ssid_len: s.ssid_len,
                    channel: s.channel,
                    band: s.band,
                    rssi_dbm: s.rssi_dbm,
                    bssid: s.bssid,
                    security: security(s.security),
                    mfp: s.mfp,
                },
            }
        }
        raw::nrf70_facade_event_kind_NRF70_FACADE_EVENT_SCAN_COMPLETE => Event::ScanComplete {
            generation,
            status: e.status,
        },
        raw::nrf70_facade_event_kind_NRF70_FACADE_EVENT_AUTH => Event::Auth {
            generation,
            status: e.status,
            frequency_mhz: e.frequency_mhz,
        },
        raw::nrf70_facade_event_kind_NRF70_FACADE_EVENT_ASSOC => Event::Assoc {
            generation,
            status: e.status,
            frequency_mhz: e.frequency_mhz,
        },
        raw::nrf70_facade_event_kind_NRF70_FACADE_EVENT_DISCONNECTED => Event::Disconnected {
            generation,
            reason_code: e.reason_code,
        },
        raw::nrf70_facade_event_kind_NRF70_FACADE_EVENT_LINK => Event::Link {
            generation,
            up: e.link_up != 0,
            frequency_mhz: e.frequency_mhz,
            rssi_dbm: e.rssi_dbm,
        },
        raw::nrf70_facade_event_kind_NRF70_FACADE_EVENT_TX_COMPLETE => Event::TxComplete {
            generation,
            token: e.token,
            status: e.status,
        },
        raw::nrf70_facade_event_kind_NRF70_FACADE_EVENT_RX_READY => Event::RxReady { generation },
        raw::nrf70_facade_event_kind_NRF70_FACADE_EVENT_FIRMWARE_RESTART => {
            Event::FirmwareRestart { generation }
        }
        raw::nrf70_facade_event_kind_NRF70_FACADE_EVENT_PORT_AUTHORIZED => {
            Event::PortAuthorized { generation }
        }
        raw::nrf70_facade_event_kind_NRF70_FACADE_EVENT_HANDSHAKE_FAILED => {
            Event::HandshakeFailed {
                generation,
                status: e.status,
                reason_code: e.reason_code,
            }
        }
        raw::nrf70_facade_event_kind_NRF70_FACADE_EVENT_LINK_INFO => Event::LinkInfo {
            generation,
            status: e.status,
        },
        _ => Event::Fatal {
            generation,
            reason: e.status,
        },
    })
}
