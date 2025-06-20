use alloc::vec::Vec;
use core::alloc::Layout;
use core::ffi::c_void;
use core::marker::PhantomData;
use core::num::NonZero;
use core::ops::{Add, BitAnd, Deref, DerefMut, Shr};
use core::ptr::NonNull;
use core::slice::SliceIndex;
use core::{mem, ptr};

use libc::{MAP_ANONYMOUS, MAP_NORESERVE, MAP_PRIVATE, PROT_READ, PROT_WRITE};

use crate::global::{global_ctx, GlobalCtx};
use crate::hooks::{
    BsanAllocHooks, BsanHooks, MUnmap, BSAN_MAP_FLAGS, BSAN_PROT_FLAGS, DEFAULT_HOOKS,
};
use crate::utils;

/// Different targets have a different number
/// of significant bits in their pointer representation.
/// On 32-bit platforms, all 32-bits are addressable. Most
/// 64-bit platforms only use 48-bits. Following the LLVM Project,
/// we hard-code these values based on the underlying architecture.
/// Most, if not all 64 bit architectures use 48-bits. However, the
/// Armv8-A spec allows addressing 52 or 56 bits as well. No processors
/// implement this yet, though, so we can use target_pointer_width.
#[cfg(target_pointer_width = "64")]
static VA_BITS: u32 = 48;

#[cfg(target_pointer_width = "32")]
static VA_BITS: u32 = 32;

#[cfg(target_pointer_width = "16")]
static VA_BITS: u32 = 16;

// The number of bytes in a pointer
static PTR_BYTES: u32 = mem::size_of::<usize>().ilog2();

// The number of addressable, word-aligned, pointer-sized chunks
static NUM_ADDR_CHUNKS: u32 = VA_BITS - PTR_BYTES;

// We have 2^L2_POWER entries in the second level of the page table
// Adding 1 ensures that we have more second-level entries than first
// level entries if the number of addressable chunks is odd.
static L2_POWER: u32 = NUM_ADDR_CHUNKS.strict_add(1).strict_div(2);

// We have 2^L1_POWER entries in the first level of the page table
static L1_POWER: u32 = NUM_ADDR_CHUNKS.strict_div(2);

// The number of entries in the second level of the page table
static L2_LEN: usize = 2_usize.pow(L2_POWER);

// The number of entries in the first level of the page table
static L1_LEN: usize = 2_usize.pow(L1_POWER);

// The protection flags for the page tables
static PROT_SHADOW: i32 = PROT_READ | PROT_WRITE;

// The flags for the page tables
static MAP_SHADOW: i32 = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;

/// Converts an address into a pair of indices into the first and second
/// levels of the shadow page table.
#[inline(always)]
pub fn table_indices(address: usize) -> (usize, usize) {
    let as_num_ptrs = address.shr(PTR_BYTES);

    #[cfg(target_endian = "little")]
    let l1_index = address.shr(L2_POWER);
    #[cfg(target_endian = "big")]
    let l1_index = address.shl(L2_POWER);

    let l1_index = l1_index.bitand(2_usize.pow(L1_POWER) - 1);

    let l2_mask = 2_usize.pow(L2_POWER) - 1;

    #[cfg(target_endian = "little")]
    let l2_index = address.bitand(l2_mask);

    #[cfg(target_endian = "big")]
    let l2_index = address.bitand(l2_mask);

    (l1_index, l2_index)
}

#[repr(C)]
#[derive(Debug)]
pub struct ShadowHeap<T> {
    // First level table containing pointers to second level tables
    table: NonNull<[*mut [T; L2_LEN]; L1_LEN]>,
    munmap: MUnmap,
    l2_blocks: Vec<usize, BsanAllocHooks>,
}

unsafe impl<T> Sync for ShadowHeap<T> {}

impl<T> ShadowHeap<T> {
    pub fn new(hooks: &BsanHooks) -> Self {
        unsafe {
            let table: NonNull<[*mut [T; L2_LEN]; L1_LEN]> = {
                let size_bytes =
                    NonZero::new_unchecked(mem::size_of::<[*mut [T; L2_LEN]; L1_LEN]>());
                utils::mmap(hooks.mmap_ptr, size_bytes, BSAN_PROT_FLAGS, BSAN_MAP_FLAGS)
            };

            Self {
                table,
                munmap: hooks.munmap_ptr,
                l2_blocks: Vec::<usize, BsanAllocHooks>::new_in(hooks.alloc),
            }
        }
    }

    unsafe fn allocate_l2_table(&self, hooks: &BsanHooks) -> *mut [T; L2_LEN] {
        let l2_page: NonNull<[T; L2_LEN]> = unsafe {
            let size_bytes = NonZero::new_unchecked(mem::size_of::<T>() * L2_LEN);
            utils::mmap(hooks.mmap_ptr, size_bytes, BSAN_PROT_FLAGS, BSAN_MAP_FLAGS)
        };
        l2_page.as_ptr()
    }
}

impl<T: Default + Copy> ShadowHeap<T> {
    pub fn load_prov(&self, addr: usize) -> T {
        unsafe {
            let (l1_index, l2_index) = table_indices(addr);

            let l2_table: *mut [T; L2_LEN] = (*self.table.as_ptr())[l1_index];

            if l2_table.is_null() {
                return T::default();
            }

            (*l2_table)[l2_index]
        }
    }

    pub fn store_prov(&self, hooks: &BsanHooks, prov: *const T, addr: usize) {
        let (l1_index, l2_index) = table_indices(addr);
        unsafe {
            let l2_table_ptr: *mut *mut [T; L2_LEN] = &raw mut (*self.table.as_ptr())[l1_index];

            if (*l2_table_ptr).is_null() {
                *l2_table_ptr = self.allocate_l2_table(hooks);
            }

            let slot: *mut T = &raw mut ((**l2_table_ptr)[l2_index]);
            *slot = *prov;
        }
    }
}

impl<T> Drop for ShadowHeap<T> {
    fn drop(&mut self) {
        unsafe {
            // Free all L2 tables
            for i in self.l2_blocks.drain(..) {
                let l2_table = (*self.table.as_ptr())[i];
                if !l2_table.is_null() {
                    unsafe {
                        let l2_table_size = NonZero::new_unchecked(mem::size_of::<T>() * L2_LEN);
                        let l2_table = NonNull::new_unchecked(l2_table);
                        utils::munmap(self.munmap, l2_table, l2_table_size);
                    }
                }
            }

            unsafe {
                let size_bytes =
                    NonZero::new_unchecked(mem::size_of::<[*mut [T; L2_LEN]; L1_LEN]>());
                utils::munmap::<[*mut [T; L2_LEN]; L1_LEN]>(self.munmap, self.table, size_bytes);
            }
            // Free L1 table
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::shadow::*;

    #[derive(Default, Debug, Copy, Clone)]
    struct TestProv {
        value: u128,
    }

    #[test]
    fn test_table_indices() {
        let addr = 0x1234_5678_1234_5678;
        let (l1, l2) = table_indices(addr);
        assert!(l1 < L1_LEN);
        assert!(l2 < L2_LEN);
    }

    #[test]
    fn test_shadow_heap_creation() {
        ShadowHeap::<TestProv>::new(&DEFAULT_HOOKS);
    }

    #[test]
    fn test_load_null_prov() {
        let heap = ShadowHeap::<TestProv>::new(&DEFAULT_HOOKS);
        let prov = unsafe { heap.load_prov(0) };
        assert_eq!(prov.value, 0);
    }

    #[test]
    fn test_store_and_load_prov() {
        let heap = ShadowHeap::<TestProv>::new(&DEFAULT_HOOKS);
        let test_prov = TestProv { value: 42 };
        // Use an address that will split into non-zero indices for both L1 and L2
        let addr = 0x1234_5678_1234_5678;
        unsafe {
            heap.store_prov(&DEFAULT_HOOKS, &test_prov, addr);
            let loaded_prov = heap.load_prov(addr);
            assert_eq!(loaded_prov.value, test_prov.value);
        }
    }

    #[test]
    fn smoke() {
        let heap = ShadowHeap::<TestProv>::new(&DEFAULT_HOOKS);
        // Create test data
        const NUM_OPERATIONS: usize = 10;
        let test_values: Vec<TestProv> =
            (0..NUM_OPERATIONS).map(|i| TestProv { value: (i % 255) as u128 }).collect();

        // Use a properly aligned base address
        const BASE_ADDR: usize = 0x7FFF_FFFF_AA00;
        assert_eq!(BASE_ADDR % 8, 0);
        unsafe {
            for (i, test_value) in test_values.iter().enumerate().take(NUM_OPERATIONS) {
                let addr = BASE_ADDR + (i * 8);
                heap.store_prov(&DEFAULT_HOOKS, test_value, addr);
                let prov = heap.load_prov(addr);
                assert_eq!(prov.value, test_value.value);
            }

            for (i, test_value) in test_values.iter().enumerate().take(NUM_OPERATIONS) {
                let addr = BASE_ADDR + (i * 8);
                let prov = heap.load_prov(addr);
                assert_eq!(prov.value, test_value.value);
                heap.store_prov(&DEFAULT_HOOKS, test_value, addr);
            }
        }
    }
}
