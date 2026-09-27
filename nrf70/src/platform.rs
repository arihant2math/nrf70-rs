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
    /// Sole entropy source for the WPA2 EAPOL-Key SNonce: MUST be backed by a
    /// cryptographically secure TRNG, or the 4-way handshake is breakable.
    fn random_u8(&mut self) -> u8;
    fn host_irq_active(&self) -> bool;
    /// Records a message supplied by the C facade.
    ///
    /// # Safety
    /// `message` must be null or point to a valid, nul-terminated string for
    /// the duration of this call.
    unsafe fn log(&mut self, _level: u8, _message: *const c_char) {}
    /// Records a fatal error supplied by the C facade.
    ///
    /// # Safety
    /// `message` must be null or point to a valid, nul-terminated string for
    /// the duration of this call.
    unsafe fn fatal(&mut self, _reason: i32, _message: *const c_char) {}
}

/// Maps a `Bus` result onto the C ABI's 0/-1 convention.
fn code<E>(result: Result<(), E>) -> i32 {
    result.map(|_| 0).unwrap_or(-1)
}
/// The C side requires address, pointer, and length to be four-byte aligned.
fn word_aligned(address: u32, buffer: &[u8]) -> bool {
    ((address as usize) | (buffer.as_ptr() as usize) | buffer.len()) & 3 == 0
}

/// Rust-owned platform state: hardware tokens plus a dedicated bounded control arena.
/// Put this value in a `StaticCell`; no unconstrained global allocator is used.
///
/// The arena is borrowed rather than owned so it can be a plain `static`:
/// `Arena::new()` is const and all zero, so it lands in `.bss`, whereas a
/// `Platform` built at runtime is assembled on the stack before it is moved
/// into its cell, and the arena is usually far larger than the stack.
pub struct Platform<B, const ARENA: usize> {
    bus: UnsafeCell<B>,
    arena: &'static Arena<ARENA>,
}
unsafe impl<B: Send, const N: usize> Sync for Platform<B, N> {}
impl<B, const N: usize> Platform<B, N> {
    /// `arena` must be used by no other `Platform`.
    pub const fn new(bus: B, arena: &'static Arena<N>) -> Self {
        Self {
            bus: UnsafeCell::new(bus),
            arena,
        }
    }
    pub fn arena(&self) -> &Arena<N> {
        self.arena
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
        code(self.bus().power_on())
    }
    fn power_off(&self) {
        self.bus().power_off()
    }
    fn bus_init(&self) -> i32 {
        code(self.bus().bus_init())
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
        code(self.bus().write_reg32(a, v))
    }
    fn read(&self, a: u32, d: &mut [u8]) -> i32 {
        if !word_aligned(a, d) {
            return -1;
        }
        code(self.bus().read(a, d))
    }
    fn write(&self, a: u32, s: &[u8]) -> i32 {
        if !word_aligned(a, s) {
            return -1;
        }
        code(self.bus().write(a, s))
    }
    fn sleep(&self) -> i32 {
        code(self.bus().sleep())
    }
    fn wake(&self) -> i32 {
        code(self.bus().wake())
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
    unsafe fn log(&self, l: u8, m: *const c_char) {
        unsafe { self.bus().log(l, m) }
    }
    unsafe fn fatal(&self, r: i32, m: *const c_char) {
        unsafe { self.bus().fatal(r, m) }
    }
}
