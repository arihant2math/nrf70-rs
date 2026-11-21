use core::{
    cell::{RefCell, UnsafeCell},
    ptr,
};
use critical_section::Mutex;

const BLOCKS: usize = 192;
#[derive(Clone, Copy)]
struct Block {
    offset: u32,
    size: u32,
    used: bool,
    valid: bool,
}
impl Block {
    const EMPTY: Self = Self {
        offset: 0,
        size: 0,
        used: false,
        valid: false,
    };
}
struct State {
    blocks: [Block; BLOCKS],
    used: u32,
    high: u32,
    failures: u32,
}
impl State {
    const fn new(size: u32) -> Self {
        let mut blocks = [Block::EMPTY; BLOCKS];
        blocks[0] = Block {
            offset: 0,
            size,
            used: false,
            valid: true,
        };
        Self {
            blocks,
            used: 0,
            high: 0,
            failures: 0,
        }
    }
}
#[repr(align(8))]
struct Storage<const N: usize>([u8; N]);

/// Bounded, coalescing arena used exclusively by the C Wi-Fi control stack.
pub struct Arena<const N: usize> {
    storage: UnsafeCell<Storage<N>>,
    state: Mutex<RefCell<State>>,
}
unsafe impl<const N: usize> Sync for Arena<N> {}
impl<const N: usize> Arena<N> {
    pub const fn new() -> Self {
        Self {
            storage: UnsafeCell::new(Storage([0; N])),
            state: Mutex::new(RefCell::new(State::new(N as u32))),
        }
    }
    pub(crate) unsafe fn alloc(&self, size: u32, align: u32, zeroed: bool) -> *mut u8 {
        if align > 8 || !align.is_power_of_two() || N > u32::MAX as usize {
            return ptr::null_mut();
        }
        // The C stack expects malloc(0)/zalloc(0) to succeed with a unique,
        // freeable pointer (e.g. hal_api.c's zero-length RX pool tables), so a
        // zero-size request still takes one granule.
        let Some(size) = size.max(1).checked_add(7).map(|value| value & !7) else {
            return ptr::null_mut();
        };
        let offset = critical_section::with(|cs| {
            let mut s = self.state.borrow(cs).borrow_mut();
            let found = s
                .blocks
                .iter()
                .position(|b| b.valid && !b.used && b.size >= size);
            let Some(i) = found else {
                s.failures += 1;
                return None;
            };
            let b = s.blocks[i];
            if b.size > size {
                let Some(j) = s.blocks.iter().position(|x| !x.valid) else {
                    s.failures += 1;
                    return None;
                };
                s.blocks[j] = Block {
                    offset: b.offset + size,
                    size: b.size - size,
                    used: false,
                    valid: true,
                };
                s.blocks[i].size = size;
            }
            s.blocks[i].used = true;
            s.used += size;
            s.high = s.high.max(s.used);
            Some(b.offset)
        });
        let Some(offset) = offset else {
            return ptr::null_mut();
        };
        let p = unsafe { (*self.storage.get()).0.as_mut_ptr().add(offset as usize) };
        if zeroed {
            unsafe { ptr::write_bytes(p, 0, size as usize) }
        }
        p
    }
    pub(crate) unsafe fn free(&self, p: *mut u8) {
        if p.is_null() {
            return;
        }
        let base = unsafe { (*self.storage.get()).0.as_mut_ptr() as usize };
        let addr = p as usize;
        if addr < base || addr >= base + N {
            return;
        }
        let off = (addr - base) as u32;
        critical_section::with(|cs| {
            let mut s = self.state.borrow(cs).borrow_mut();
            let Some(i) = s
                .blocks
                .iter()
                .position(|b| b.valid && b.used && b.offset == off)
            else {
                return;
            };
            s.blocks[i].used = false;
            s.used -= s.blocks[i].size;
            // Free blocks are kept coalesced, so only the freed block's
            // neighbours can merge with it.
            let free = |b: &Block| b.valid && !b.used;
            let end = off + s.blocks[i].size;
            if let Some(next) = s.blocks.iter().position(|b| free(b) && b.offset == end) {
                s.blocks[i].size += s.blocks[next].size;
                s.blocks[next] = Block::EMPTY;
            }
            if let Some(prev) = s
                .blocks
                .iter()
                .position(|b| free(b) && b.offset + b.size == off)
            {
                s.blocks[prev].size += s.blocks[i].size;
                s.blocks[i] = Block::EMPTY;
            }
        });
    }
    pub fn used(&self) -> u32 {
        critical_section::with(|cs| self.state.borrow(cs).borrow().used)
    }
    pub fn high_water(&self) -> u32 {
        critical_section::with(|cs| self.state.borrow(cs).borrow().high)
    }
    pub fn failures(&self) -> u32 {
        critical_section::with(|cs| self.state.borrow(cs).borrow().failures)
    }
}
impl<const N: usize> Default for Arena<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Arena;

    #[test]
    fn reuses_and_coalesces_freed_blocks() {
        let arena = Arena::<128>::new();
        unsafe {
            let first = arena.alloc(40, 8, true);
            let second = arena.alloc(40, 8, false);
            assert!(!first.is_null() && !second.is_null());
            arena.free(first);
            arena.free(second);
            let whole = arena.alloc(120, 8, false);
            assert!(!whole.is_null());
            assert_eq!(arena.used(), 120);
            assert_eq!(arena.high_water(), 120);
            arena.free(whole);
            assert_eq!(arena.used(), 0);
        }
    }

    #[test]
    fn zero_size_alloc_returns_freeable_pointer() {
        let arena = Arena::<128>::new();
        unsafe {
            let empty = arena.alloc(0, 8, true);
            assert!(!empty.is_null());
            assert_eq!(arena.used(), 8);
            let other = arena.alloc(0, 8, false);
            assert!(!other.is_null());
            assert_ne!(empty, other);
            arena.free(empty);
            arena.free(other);
            assert_eq!(arena.used(), 0);
        }
    }
}
