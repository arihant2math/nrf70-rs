#![allow(clippy::mut_from_ref)]

use crate::Arena;
use core::{cell::UnsafeCell, ffi::c_char};

/// Synchronous nRF7002 SPI/GPIO backend. It is owned for the lifetime of the driver.
/// Implementations must enforce the board's IOVDD/BUCKEN sequence in `power_on/off`.
pub trait Bus {
    type Error;
    fn power_on(&mut self) -> Result<(), Self::Error>;
    fn power_off(&mut self);
    fn bus_init(&mut self) -> Result<(), Self::Error>;
    fn bus_deinit(&mut self);
    fn read_reg32(&mut self, address: u32) -> Result<u32, Self::Error>;
    fn write_reg32(&mut self, address: u32, value: u32) -> Result<(), Self::Error>;
    /// Address, pointer, and length have already been checked for four-byte alignment.
    fn read(&mut self, address: u32, dst: &mut [u8]) -> Result<(), Self::Error>;
    fn write(&mut self, address: u32, src: &[u8]) -> Result<(), Self::Error>;
    fn sleep(&mut self) -> Result<(), Self::Error>;
    fn wake(&mut self) -> Result<(), Self::Error>;
    fn power_status(&mut self) -> Result<i32, Self::Error>;
    fn delay_us(&mut self, delay: u32);
    fn now_us(&self) -> u32;
    /// Returns one byte of entropy. This is the sole entropy source for WPA2
    /// nonce generation (the supplicant's EAPOL-Key SNonce), so it MUST be
    /// backed by a cryptographically secure TRNG (the plan's CRACEN-backed
    /// entropy service on the target board). A counter or weak PRNG here
    /// makes the handshake nonces predictable and breaks the security of the
    /// 4-way handshake. The op is mandatory: the C side treats a missing
    /// implementation as fatal-quality and substitutes a constant 0.
    fn random_u8(&mut self) -> u8;
    fn host_irq_active(&self) -> bool;
    fn log(&mut self, _level: u8, _message: *const c_char) {}
    fn fatal(&mut self, _reason: i32, _message: *const c_char) {}
}

/// Rust-owned platform state: hardware tokens plus a dedicated bounded control arena.
/// Put this value in a `StaticCell`; no unconstrained global allocator is used.
pub struct Platform<B, const ARENA: usize> {
    bus: UnsafeCell<B>,
    arena: Arena<ARENA>,
}
unsafe impl<B: Send, const N: usize> Sync for Platform<B, N> {}
impl<B, const N: usize> Platform<B, N> {
    pub const fn new(bus: B) -> Self {
        Self {
            bus: UnsafeCell::new(bus),
            arena: Arena::new(),
        }
    }
    pub fn arena(&self) -> &Arena<N> {
        &self.arena
    }
}
impl<B: Bus + Send, const N: usize> Platform<B, N> {
    // Safety is provided by nrf70-sys::Platform's serialized-runner contract.
    #[allow(clippy::mut_from_ref)]
    fn bus(&self) -> &mut B {
        unsafe { &mut *self.bus.get() }
    }
    pub(crate) fn now_us_for_runner(&self) -> u32 {
        self.bus().now_us()
    }
}
unsafe impl<B: Bus + Send, const N: usize> nrf70_sys::Platform for Platform<B, N> {
    unsafe fn alloc(&self, size: u32, align: u32, zeroed: bool) -> *mut u8 {
        unsafe { self.arena.alloc(size, align, zeroed) }
    }
    unsafe fn free(&self, p: *mut u8) {
        unsafe { self.arena.free(p) }
    }
    fn power_on(&self) -> i32 {
        self.bus().power_on().map(|_| 0).unwrap_or(-1)
    }
    fn power_off(&self) {
        self.bus().power_off()
    }
    fn bus_init(&self) -> i32 {
        self.bus().bus_init().map(|_| 0).unwrap_or(-1)
    }
    fn bus_deinit(&self) {
        self.bus().bus_deinit()
    }
    fn read_reg32(&self, a: u32, v: &mut u32) -> i32 {
        match self.bus().read_reg32(a) {
            Ok(x) => {
                *v = x;
                0
            }
            Err(_) => -1,
        }
    }
    fn write_reg32(&self, a: u32, v: u32) -> i32 {
        self.bus().write_reg32(a, v).map(|_| 0).unwrap_or(-1)
    }
    fn read(&self, a: u32, d: &mut [u8]) -> i32 {
        if ((a as usize) | (d.as_ptr() as usize) | d.len()) & 3 != 0 {
            return -1;
        }
        self.bus().read(a, d).map(|_| 0).unwrap_or(-1)
    }
    fn write(&self, a: u32, s: &[u8]) -> i32 {
        if ((a as usize) | (s.as_ptr() as usize) | s.len()) & 3 != 0 {
            return -1;
        }
        self.bus().write(a, s).map(|_| 0).unwrap_or(-1)
    }
    fn sleep(&self) -> i32 {
        self.bus().sleep().map(|_| 0).unwrap_or(-1)
    }
    fn wake(&self) -> i32 {
        self.bus().wake().map(|_| 0).unwrap_or(-1)
    }
    fn power_status(&self) -> i32 {
        self.bus().power_status().unwrap_or(-1)
    }
    fn delay_us(&self, u: u32) {
        self.bus().delay_us(u)
    }
    fn now_us(&self) -> u32 {
        self.bus().now_us()
    }
    fn random_u8(&self) -> u8 {
        self.bus().random_u8()
    }
    fn host_irq_active(&self) -> bool {
        self.bus().host_irq_active()
    }
    fn log(&self, l: u8, m: *const c_char) {
        self.bus().log(l, m)
    }
    fn fatal(&self, r: i32, m: *const c_char) {
        self.bus().fatal(r, m)
    }
}
