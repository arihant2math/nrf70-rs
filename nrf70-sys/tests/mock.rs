#![cfg(feature = "mock")]
use core::ffi::c_char;

struct Mock;
unsafe impl nrf70_sys::Platform for Mock {
    unsafe fn alloc(&self, _: u32, _: u32, _: bool) -> *mut u8 {
        core::ptr::null_mut()
    }
    unsafe fn free(&self, _: *mut u8) {}
    fn power_on(&self) -> i32 {
        0
    }
    fn power_off(&self) {}
    fn bus_init(&self) -> i32 {
        0
    }
    fn bus_deinit(&self) {}
    fn read_reg32(&self, _: u32, v: &mut u32) -> i32 {
        *v = 0;
        0
    }
    fn write_reg32(&self, _: u32, _: u32) -> i32 {
        0
    }
    fn read(&self, _: u32, _: &mut [u8]) -> i32 {
        0
    }
    fn write(&self, _: u32, _: &[u8]) -> i32 {
        0
    }
    fn sleep(&self) -> i32 {
        0
    }
    fn wake(&self) -> i32 {
        0
    }
    fn power_status(&self) -> i32 {
        0
    }
    fn delay_us(&self, _: u32) {}
    fn now_us(&self) -> u32 {
        42
    }
    fn random_u8(&self) -> u8 {
        4
    }
    fn host_irq_active(&self) -> bool {
        false
    }
    fn log(&self, _: u8, _: *const c_char) {}
}
static MOCK: Mock = Mock;

fn target(
    ssid: &[u8],
    bssid: [u8; 6],
    frequency_mhz: u16,
    security: nrf70_sys::Security,
    credential_kind: u8,
    credential: &[u8],
) -> nrf70_sys::ConnectTarget {
    let mut s = [0u8; 32];
    s[..ssid.len()].copy_from_slice(ssid);
    let mut c = [0u8; 64];
    c[..credential.len()].copy_from_slice(credential);
    nrf70_sys::ConnectTarget {
        ssid: s,
        ssid_len: ssid.len() as u8,
        bssid,
        frequency_mhz,
        security,
        mfp: nrf70_sys::MFP_DISABLED,
        credential_kind,
        credential_len: credential.len() as u8,
        credential: c,
    }
}

fn expect_auth_assoc() {
    assert!(matches!(
        unsafe { nrf70_sys::event_pop() },
        Some(nrf70_sys::Event::Auth { status: 0, .. })
    ));
    assert!(matches!(
        unsafe { nrf70_sys::event_pop() },
        Some(nrf70_sys::Event::Assoc { status: 0, .. })
    ));
}

fn expect_disconnected() {
    assert!(matches!(
        unsafe { nrf70_sys::event_pop() },
        Some(nrf70_sys::Event::Disconnected { .. })
    ));
    drain();
}

fn drain() {
    while unsafe { nrf70_sys::event_pop() }.is_some() {}
}

/// The facade is a single global, so all Phase-3 scenarios run in one test.
#[test]
fn phase3_facade_connect_flows() {
    unsafe { nrf70_sys::init(&MOCK, [2, 0, 0, 0, 0, 1], *b"US").unwrap() };

    // (a) open connect from a scan result, data loopback, disconnect.
    let mut q = nrf70_sys::ScanRequest {
        channel_count: 1,
        ..Default::default()
    };
    q.channels[0] = nrf70_sys::Channel {
        band: 1,
        channel: 44,
    };
    unsafe { nrf70_sys::scan_start(&q).unwrap() };
    let ap = match unsafe { nrf70_sys::event_pop() }.unwrap() {
        nrf70_sys::Event::ScanResult { result, .. } => {
            assert_eq!(result.security, nrf70_sys::Security::Open);
            result
        }
        e => panic!("unexpected {e:?}"),
    };
    assert!(matches!(
        unsafe { nrf70_sys::event_pop() },
        Some(nrf70_sys::Event::ScanComplete { status: 0, .. })
    ));
    let open = target(
        &ap.ssid[..ap.ssid_len as usize],
        ap.bssid,
        5000 + ap.channel as u16 * 5,
        nrf70_sys::Security::Open,
        nrf70_sys::CREDENTIAL_NONE,
        &[],
    );
    unsafe { nrf70_sys::connect_start(&open).unwrap() };
    expect_auth_assoc();
    assert!(matches!(
        unsafe { nrf70_sys::event_pop() },
        Some(nrf70_sys::Event::Link { up: true, .. })
    ));
    let mut frame = [0u8; 64];
    frame[..6].fill(0xff);
    frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);
    unsafe { nrf70_sys::tx(7, &frame).unwrap() };
    assert!(matches!(
        unsafe { nrf70_sys::event_pop() },
        Some(nrf70_sys::Event::TxComplete {
            token: 7,
            status: 0,
            ..
        })
    ));
    assert!(matches!(
        unsafe { nrf70_sys::event_pop() },
        Some(nrf70_sys::Event::RxReady { .. })
    ));
    let mut received = [0u8; nrf70_sys::MAX_FRAME_LEN];
    let meta = unsafe { nrf70_sys::rx_pop(&mut received).unwrap().unwrap() };
    assert_eq!(meta.length, 64);
    assert_eq!(&received[..64], &frame);
    unsafe { nrf70_sys::disconnect(3).unwrap() };
    expect_disconnected();

    // (b) WPA2-Personal success: connect_start enqueues AUTH, ASSOC, and
    // LINK up (linked, not yet authorized); PORT_AUTHORIZED only arrives
    // from the next process() call. In the window between LINK up and
    // PORT_AUTHORIZED — the 4-way handshake — ordinary data TX must be
    // rejected (the controlled-port data gate).
    let wpa2 = target(
        b"phase3-wpa2-5g",
        [2, 0, 0, 0, 0, 3],
        5220,
        nrf70_sys::Security::Wpa2Psk,
        nrf70_sys::CREDENTIAL_PASSPHRASE,
        b"correct horse",
    );
    unsafe { nrf70_sys::connect_start(&wpa2).unwrap() };
    expect_auth_assoc();
    assert!(matches!(
        unsafe { nrf70_sys::event_pop() },
        Some(nrf70_sys::Event::Link { up: true, .. })
    ));
    // PORT_AUTHORIZED must not be queued yet, and data TX must be rejected
    // while the handshake is in flight.
    assert!(unsafe { nrf70_sys::event_pop() }.is_none());
    assert_eq!(
        unsafe { nrf70_sys::tx(9, &frame) },
        Err(nrf70_sys::Status::NotConnected)
    );
    unsafe { nrf70_sys::process(8) };
    assert!(matches!(
        unsafe { nrf70_sys::event_pop() },
        Some(nrf70_sys::Event::PortAuthorized { .. })
    ));
    // The port is authorized: data TX now succeeds.
    unsafe { nrf70_sys::tx(10, &frame).unwrap() };
    drain();
    let mut scratch = [0u8; nrf70_sys::MAX_FRAME_LEN];
    while matches!(unsafe { nrf70_sys::rx_pop(&mut scratch) }, Ok(Some(_))) {}
    unsafe { nrf70_sys::disconnect(3).unwrap() };
    expect_disconnected();

    // (c) wrong password: HANDSHAKE_FAILED with reason 23, no link, no data path.
    let wrong = target(
        b"phase3-wpa2-5g",
        [2, 0, 0, 0, 0, 3],
        5220,
        nrf70_sys::Security::Wpa2Psk,
        nrf70_sys::CREDENTIAL_PASSPHRASE,
        b"wrong-password",
    );
    unsafe { nrf70_sys::connect_start(&wrong).unwrap() };
    expect_auth_assoc();
    match unsafe { nrf70_sys::event_pop() } {
        Some(nrf70_sys::Event::HandshakeFailed {
            status,
            reason_code,
            ..
        }) => {
            assert_eq!(status, nrf70_sys::Status::Io as i32);
            assert_eq!(reason_code, 23);
        }
        e => panic!("unexpected {e:?}"),
    }
    // The link must never rise after a failed handshake.
    while let Some(e) = unsafe { nrf70_sys::event_pop() } {
        assert!(
            !matches!(e, nrf70_sys::Event::Link { up: true, .. }),
            "{e:?}"
        );
    }
    assert_eq!(
        unsafe { nrf70_sys::tx(8, &frame) },
        Err(nrf70_sys::Status::NotConnected)
    );
    unsafe { nrf70_sys::connect_abort(3).unwrap() };
    expect_disconnected();

    // (d) request validation.
    let short = target(
        b"phase3-wpa2-5g",
        [2, 0, 0, 0, 0, 3],
        5220,
        nrf70_sys::Security::Wpa2Psk,
        nrf70_sys::CREDENTIAL_PASSPHRASE,
        b"seven77",
    );
    assert_eq!(
        unsafe { nrf70_sys::connect_start(&short) },
        Err(nrf70_sys::Status::Invalid)
    );
    let open_with_credential = target(
        b"phase3-open-5g",
        [2, 0, 0, 0, 0, 2],
        5220,
        nrf70_sys::Security::Open,
        nrf70_sys::CREDENTIAL_PASSPHRASE,
        b"passphrase",
    );
    assert_eq!(
        unsafe { nrf70_sys::connect_start(&open_with_credential) },
        Err(nrf70_sys::Status::Invalid)
    );
    drain();
    unsafe { nrf70_sys::deinit().unwrap() };
}
