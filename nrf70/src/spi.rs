#![allow(clippy::result_unit_err)]

use crate::Bus;
use embedded_hal::spi::{Operation, SpiDevice};

const PACKET_RAM_START: u32 = 0x0c0000;
const PACKET_RAM_END: u32 = 0x0f0fff;
const CLOCK_CONTROL: u32 = 0x048c20;
const RPU_AWAKE: u8 = 1 << 1;
const RPU_WAKE: u8 = 1;

/// Board-owned GPIO, delay, monotonic clock, entropy, and HOST_IRQ operations.
/// `power_on/off` must implement the reviewed IOVDD/BUCKEN sequencing contract.
pub trait BoardControl {
    fn power_on(&mut self) -> Result<(), ()>;
    fn power_off(&mut self);
    fn delay_us(&mut self, us: u32);
    fn now_us(&self) -> u32;
    fn random_u8(&mut self) -> u8;
    fn host_irq_active(&self) -> bool;
}

/// Four-wire nRF7002 SPI transport. `D` owns the SPIM peripheral and CS token;
/// `C` owns HOST_IRQ, BUCKEN, and IOVDD_CTL. Phase 1 operates it at 8 MHz.
pub struct SpiTransport<D, C> {
    device: D,
    control: C,
}
impl<D, C> SpiTransport<D, C> {
    pub const fn new(device: D, control: C) -> Self {
        Self { device, control }
    }
}

impl<D: SpiDevice<u8>, C: BoardControl> SpiTransport<D, C> {
    fn status_read(&mut self, opcode: u8) -> Result<u8, ()> {
        let tx = [opcode, 0, 0, 0, 0, 0];
        let mut rx = [0u8; 6];
        self.device.transfer(&mut rx, &tx).map_err(|_| ())?;
        Ok(rx[1])
    }
    fn status_write(&mut self, opcode: u8, value: u8) -> Result<(), ()> {
        self.device.write(&[opcode, value]).map_err(|_| ())
    }
    /// The wakeup write can be missed if it lands while the chip is still
    /// ramping its rails, so retry the whole handshake a few times.
    fn wake_rpu(&mut self) -> Result<(), ()> {
        (0..3).find_map(|_| self.try_wake_rpu().ok()).ok_or(())
    }
    /// Reads `opcode` up to ten times waiting for `mask` to set, delaying 1 ms
    /// after every miss (including the last). The inner `Err` carries the last
    /// status seen; the outer `Err` is a bus failure.
    fn poll_status(&mut self, opcode: u8, mask: u8) -> Result<Result<u8, u8>, ()> {
        let mut status = 0u8;
        for _ in 0..10 {
            status = self.status_read(opcode)?;
            if status & mask != 0 {
                return Ok(Ok(status));
            }
            self.control.delay_us(1000)
        }
        Ok(Err(status))
    }
    fn try_wake_rpu(&mut self) -> Result<(), ()> {
        self.status_write(0x3f, RPU_WAKE)?;
        if let Err(_status) = self.poll_status(0x2f, RPU_WAKE)? {
            // 0x00 usually means no SPI response (power/wiring/CS), 0xff a
            // floating MISO line.
            #[cfg(feature = "defmt")]
            defmt::warn!(
                "nrf70: RPU wake not acknowledged, RDSR2={=u8:#04x}",
                _status
            );
            return Err(());
        }
        if let Err(_status) = self.poll_status(0x1f, RPU_AWAKE)? {
            #[cfg(feature = "defmt")]
            defmt::warn!(
                "nrf70: RPU wake acked but not awake, RDSR1={=u8:#04x}",
                _status
            );
            return Err(());
        }
        Ok(())
    }
    /// The four-byte SPI command header (opcode plus 24-bit address) followed
    /// by the one dummy byte the read opcodes need; writes use `[..4]`.
    const fn header(opcode: u8, address: u32) -> [u8; 5] {
        [
            opcode,
            ((address >> 16) & 0xff) as u8,
            ((address >> 8) & 0xff) as u8,
            address as u8,
            0,
        ]
    }
    fn latency(address: u32, length: usize, write: bool) -> Result<u8, ()> {
        if length == 0 || address.checked_add(length as u32 - 1).is_none() {
            return Err(());
        }
        let end = address + length as u32 - 1;
        let ranges = [
            (0x000000, 0x008fff, 1u8, false),
            (0x009000, 0x03ffff, 2, false),
            (0x040000, 0x07ffff, 1, false),
            (PACKET_RAM_START, PACKET_RAM_END, 0, false),
            (0x080000, 0x092000, 1, false),
            (0x100000, 0x134000, 1, true),
            (0x140000, 0x14c000, 1, false),
            (0x180000, 0x190000, 1, false),
            (0x200000, 0x261800, 1, true),
            (0x280000, 0x2a4000, 1, false),
            (0x300000, 0x338000, 1, false),
        ];
        for (s, e, l, rom) in ranges {
            if address >= s && end <= e {
                return if write && rom { Err(()) } else { Ok(l) };
            }
        }
        Err(())
    }
    fn write_memory(&mut self, address: u32, src: &[u8]) -> Result<(), ()> {
        if Self::latency(address, src.len(), true).is_err() {
            #[cfg(feature = "defmt")]
            defmt::error!(
                "nrf70: write_memory: unmapped or read-only range addr={=u32:#x} len={=usize}",
                address,
                src.len()
            );
            return Err(());
        }
        let header = Self::header(0x02, address | 0x800000);
        self.device
            .transaction(&mut [Operation::Write(&header[..4]), Operation::Write(src)])
            .map_err(|_e| {
                #[cfg(feature = "defmt")]
                defmt::error!(
                    "nrf70: write_memory: SPI transaction failed addr={=u32:#x} len={=usize}",
                    address,
                    src.len()
                );
            })
    }
    fn read_memory(&mut self, address: u32, dst: &mut [u8]) -> Result<(), ()> {
        let latency = Self::latency(address, dst.len(), false).map_err(|_e| {
            #[cfg(feature = "defmt")]
            defmt::error!(
                "nrf70: read_memory: unmapped range addr={=u32:#x} len={=usize}",
                address,
                dst.len()
            );
        })?;
        if latency == 0 {
            let header = Self::header(0x0b, address | 0x800000);
            return self
                .device
                .transaction(&mut [Operation::Write(&header), Operation::Read(dst)])
                .map_err(|_| ());
        }
        for (i, word) in dst.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            // Unlike the two paths above, the latency>0 windows are addressed
            // without the 0x800000 bit; this is a real hardware distinction.
            let header = Self::header(0x0b, address + i as u32 * 4);
            let mut scratch = [0u8; 12];
            let n = latency as usize * 4 + 4;
            self.device
                .transaction(&mut [
                    Operation::Write(&header),
                    Operation::Read(&mut scratch[..n]),
                ])
                .map_err(|_| ())?;
            word.copy_from_slice(&scratch[n - 4..n]);
        }
        Ok(())
    }
}
impl<D: SpiDevice<u8> + Send, C: BoardControl + Send> Bus for SpiTransport<D, C> {
    type Error = ();
    fn power_on(&mut self) -> Result<(), Self::Error> {
        self.control.power_on()
    }
    fn power_off(&mut self) {
        self.control.power_off()
    }
    fn bus_init(&mut self) -> Result<(), Self::Error> {
        self.wake_rpu()?;
        self.write_memory(CLOCK_CONTROL, &0x100u32.to_le_bytes())
    }
    fn bus_deinit(&mut self) {}
    fn read_reg32(&mut self, a: u32) -> Result<u32, Self::Error> {
        let mut b = [0; 4];
        self.read_memory(a, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn write_reg32(&mut self, a: u32, v: u32) -> Result<(), Self::Error> {
        self.write_memory(a, &v.to_le_bytes())
    }
    fn read(&mut self, a: u32, d: &mut [u8]) -> Result<(), Self::Error> {
        self.read_memory(a, d)
    }
    fn write(&mut self, a: u32, s: &[u8]) -> Result<(), Self::Error> {
        self.write_memory(a, s)
    }
    fn sleep(&mut self) -> Result<(), Self::Error> {
        self.status_write(0x3f, 0)
    }
    fn wake(&mut self) -> Result<(), Self::Error> {
        self.wake_rpu()
    }
    fn power_status(&mut self) -> Result<i32, Self::Error> {
        Ok(self.status_read(0x1f)? as i32)
    }
    fn delay_us(&mut self, u: u32) {
        self.control.delay_us(u)
    }
    fn now_us(&self) -> u32 {
        self.control.now_us()
    }
    fn random_u8(&mut self) -> u8 {
        self.control.random_u8()
    }
    fn host_irq_active(&self) -> bool {
        self.control.host_irq_active()
    }
    #[cfg(feature = "defmt")]
    unsafe fn log(&mut self, level: u8, message: *const core::ffi::c_char) {
        // SAFETY: upheld by the caller as part of `Bus::log`'s contract.
        let message = unsafe { c_message(message) };
        match level {
            0 => defmt::debug!("nrf70: {=str}", message),
            1 => defmt::info!("nrf70: {=str}", message),
            2 => defmt::warn!("nrf70: {=str}", message),
            _ => defmt::error!("nrf70: {=str}", message),
        }
    }
    #[cfg(feature = "defmt")]
    unsafe fn fatal(&mut self, reason: i32, message: *const core::ffi::c_char) {
        // SAFETY: upheld by the caller as part of `Bus::fatal`'s contract.
        let message = unsafe { c_message(message) };
        defmt::error!("nrf70: fatal {=i32}: {=str}", reason, message);
    }
}

/// The C facade only passes nul-terminated static strings (never key material).
/// # Safety `message` must be null or point to a nul-terminated string that
/// outlives the returned borrow.
#[cfg(feature = "defmt")]
unsafe fn c_message<'a>(message: *const core::ffi::c_char) -> &'a str {
    if message.is_null() {
        return "<null>";
    }
    unsafe { core::ffi::CStr::from_ptr(message) }
        .to_str()
        .unwrap_or("<non-utf8>")
}
