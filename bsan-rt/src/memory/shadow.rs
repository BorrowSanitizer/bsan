use alloc::vec::Vec;
use core::num::NonZero;
use core::ops::{BitAnd, Shr};
use core::ptr::NonNull;
use core::{mem, ptr};

use super::hooks::{BsanAllocHooks, BsanHooks, MUnmap};
use super::{mmap, munmap};
use crate::memory::{AllocResult, InternalAllocKind};

/// Different targets have a different number
/// of significant bits in their pointer representation.
/// On 32-bit platforms, all 32-bits are addressable. Most
/// 64-bit platforms only use 48-bits. Following the LLVM Project,
/// we hard-code these values based on the underlying architecture.
/// Most if not all 64 bit architectures use 48-bits. However, the
/// Armv8-A spec allows addressing 52 or 56 bits as well. No processors
/// implement this yet, though, so we can use target_pointer_width.
#[cfg(target_pointer_width = "64")]
static VA_BITS: u32 = 48;

#[cfg(target_pointer_width = "32")]
static VA_BITS: u32 = 32;

#[cfg(target_pointer_width = "16")]
static VA_BITS: u32 = 16;

// The power of the number of bytes in a pointer
static PTR_BYTES: usize = mem::size_of::<usize>();
static PTR_BYTES_POWER: u32 = PTR_BYTES.ilog2();

// The number of addressable, word-aligned, pointer-sized chunks
static NUM_ADDR_CHUNKS: u32 = VA_BITS - PTR_BYTES_POWER;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableIndex {
    l1_index: usize,
    l2_index: usize,
}

type L2Array<T> = [T; L2_LEN];
type L1Array<T> = [*mut L2Array<T>; L1_LEN];

impl TableIndex {
    fn new(address: usize) -> Self {
        let address: usize = address.shr(PTR_BYTES_POWER);

        let l1_index = Self::wrap_to_l1(address);

        let l1_index = l1_index.bitand(2_usize.pow(L1_POWER) - 1);

        let l2_mask = 2_usize.pow(L2_POWER) - 1;

        let l2_index = address.bitand(l2_mask);

        Self { l1_index, l2_index }
    }

    #[inline]
    fn wrap_to_l1(address: usize) -> usize {
        #[cfg(target_endian = "little")]
        return address.shr(L2_POWER);
        #[cfg(target_endian = "big")]
        return address.shl(L2_POWER);
    }

    #[inline]
    fn add(self, num_elements: usize) -> Self {
        let element_offset = self.l2_index + num_elements;
        let l2_index = element_offset % L2_LEN;
        let l1_index = Self::wrap_to_l1(element_offset);
        TableIndex { l1_index, l2_index }
    }

    #[inline]
    fn sub(self, num_elements: usize) -> Self {
        let l1_index = unsafe { self.l1_index.unchecked_sub(Self::wrap_to_l1(num_elements)) };
        let l2_index =
            unsafe { self.l2_index.unchecked_add(L2_LEN).unchecked_sub(num_elements) } % L2_LEN;
        TableIndex { l1_index, l2_index }
    }

    #[inline]
    fn num_remaining_in_page(&self) -> usize {
        L2_LEN - self.l2_index
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct ShadowHeap<T> {
    // First level table containing pointers to second level tables
    table: NonNull<L1Array<T>>,
    default: *const T,
    munmap: MUnmap,
    l2_blocks: Vec<usize, BsanAllocHooks>,
}

unsafe impl<T> Sync for ShadowHeap<T> {}

impl<T: Sized + Default + Copy> ShadowHeap<T> {
    pub fn new(hooks: &BsanHooks, default: *const T) -> AllocResult<Self> {
        unsafe {
            let table = {
                let size_bytes = NonZero::new_unchecked(mem::size_of::<L1Array<T>>());
                mmap(hooks.mmap_ptr, InternalAllocKind::ShadowHeap, size_bytes)?
                    .cast::<L1Array<T>>()
            };
            Ok(Self {
                table,
                default,
                munmap: hooks.munmap_ptr,
                l2_blocks: Vec::<usize, BsanAllocHooks>::new_in(hooks.alloc),
            })
        }
    }

    #[inline]
    fn get_l2(&self, idx: TableIndex) -> Option<NonNull<L2Array<T>>> {
        unsafe {
            let l2_page = (*self.table.as_ptr())[idx.l1_index];
            if l2_page.is_null() {
                None
            } else {
                Some(NonNull::new_unchecked(l2_page))
            }
        }
    }

    fn ensure_l2(&self, hooks: &BsanHooks, idx: TableIndex) -> AllocResult<NonNull<L2Array<T>>> {
        unsafe {
            let l2_table_ptr: *mut *mut L2Array<T> = &raw mut (*self.table.as_ptr())[idx.l1_index];
            if (*l2_table_ptr).is_null() {
                let size_bytes = NonZero::new_unchecked(mem::size_of::<T>() * L2_LEN);
                let l2_page = mmap(hooks.mmap_ptr, InternalAllocKind::ShadowHeap, size_bytes)?
                    .cast::<L2Array<T>>();

                *l2_table_ptr = l2_page.as_ptr();
            }
            Ok(NonNull::new_unchecked(*l2_table_ptr))
        }
    }

    pub fn clear(&self, dst: usize, num_bytes: usize) {
        if num_bytes < PTR_BYTES {
            return;
        }
        // We allow writing partial provenance values here, because if a pointer
        // is partially overwritten, then it should become invalid.
        let dst_index = TableIndex::new(dst);

        // Likewise, we want to round *up* to the nearest provenance value.
        #[cfg(target_endian = "little")]
        let mut words_remaining = num_bytes.next_multiple_of(PTR_BYTES).shr(PTR_BYTES_POWER);
        #[cfg(target_endian = "big")]
        let mut words_remaining = num_bytes.next_multiple_of(PTR_BYTES).shl(PTR_BYTES_POWER);

        while words_remaining > 0 {
            let l2_table_dst: Option<NonNull<[T; L2_LEN]>> = self.get_l2(dst_index);
            // Attempting to read from an uninitialized L2 page will return the default provenance
            // value, so we don't need to populate these pages ahead-of-time.
            if let Some(l2_table_dst) = l2_table_dst {
                let num_dst = dst_index.num_remaining_in_page();
                let num_can_write = core::cmp::min(words_remaining, num_dst);
                unsafe {
                    let dst = &raw mut (*l2_table_dst.as_ptr())[dst_index.l2_index];
                    ptr::write_bytes(dst, 0, num_can_write);
                };
                words_remaining -= num_can_write;
            } else {
                break;
            }
        }
    }

    pub fn store_consecutive(
        &self,
        hooks: &BsanHooks,
        dst: usize,
        it: impl Iterator<Item = T>,
    ) -> AllocResult<()> {
        let table_idx = TableIndex::new(dst);
        for (prov_idx, prov) in it.enumerate() {
            let idx = table_idx.add(prov_idx);
            let l2_dest = self.ensure_l2(hooks, idx)?;
            unsafe {
                (*l2_dest.as_ptr())[idx.l2_index] = prov;
            }
        }
        Ok(())
    }

    pub fn load_consecutive(&self, src: usize, len: usize, mut dest: impl Extend<T>) {
        let start_idx = TableIndex::new(src);
        for offset in 0..len {
            let curr_idx = start_idx.add(offset);
            let ptr = if let Some(curr_l2) = self.get_l2(curr_idx) {
                unsafe { &raw const (*curr_l2.as_ptr())[curr_idx.l2_index] }
            } else {
                self.default
            };
            dest.extend([unsafe { *ptr }]);
        }
    }

    /// Copy provenance values within a given range from the source to the destination.
    pub fn memcpy(
        &self,
        hooks: &BsanHooks,
        src: usize,
        dst: usize,
        num_bytes: usize,
    ) -> AllocResult<()> {
        if num_bytes < PTR_BYTES {
            return Ok(());
        }
        // We do not want to write partial provenance values, so we round the
        // starting index (L2) up to the nearest provenance value
        let mut src_index = TableIndex::new(src + PTR_BYTES).sub(1);
        let mut dst_index = TableIndex::new(dst + PTR_BYTES).sub(1);

        // Likewise, we need to divide by the number of bytes in a pointer
        // to find the number of provenance values that need to be written.
        #[cfg(target_endian = "little")]
        let mut words_remaining = num_bytes.shr(PTR_BYTES_POWER);
        #[cfg(target_endian = "big")]
        let mut words_remaining = num_bytes.shl(PTR_BYTES_POWER);

        while words_remaining > 0 {
            unsafe {
                // We want always want to ensure that the destination contains provenance values
                // for the entire range, starting from the source.
                let l2_table_src: Option<NonNull<[T; L2_LEN]>> = self.get_l2(src_index);
                let l2_table_dst: NonNull<[T; L2_LEN]> = self.ensure_l2(hooks, dst_index)?;

                let num_src = src_index.num_remaining_in_page();
                let num_dst = dst_index.num_remaining_in_page();

                let num_can_write =
                    core::cmp::min(words_remaining, core::cmp::min(num_dst, num_src));

                let dst: *mut T = &raw mut (*l2_table_dst.as_ptr())[dst_index.l2_index];

                if let Some(l2_table_src) = l2_table_src {
                    let src: *mut T = &raw mut (*l2_table_src.as_ptr())[src_index.l2_index];
                    ptr::copy(src, dst, num_can_write);
                } else {
                    // The source might not be entirely shadowed; for example, we could be copying
                    // from an uninstrumented allocation. If there are no L2 values within part or all
                    // of the range of the source,then we populate the destination with the default
                    // provenance value.
                    for offset in 0..num_can_write {
                        ptr::write(
                            &raw mut (*l2_table_dst.as_ptr())[dst_index.l2_index + offset],
                            T::default(),
                        );
                    }
                }
                src_index = src_index.add(num_can_write);
                dst_index = dst_index.add(num_can_write);

                words_remaining -= num_can_write;
            }
        }
        Ok(())
    }

    pub fn get_src(&self, addr: usize) -> *const T {
        let idx = TableIndex::new(addr);
        unsafe {
            self.get_l2(idx)
                .map(|l2_page| &raw const (*l2_page.as_ptr())[idx.l2_index])
                .unwrap_or(self.default)
        }
    }

    pub fn get_dest(&self, hooks: &BsanHooks, addr: usize) -> AllocResult<*mut T> {
        let idx = TableIndex::new(addr);
        unsafe {
            let l2_page = self.ensure_l2(hooks, idx)?;
            Ok(&raw mut (*l2_page.as_ptr())[idx.l2_index])
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
                    let l2_table_size = NonZero::new_unchecked(mem::size_of::<T>() * L2_LEN);
                    let l2_table = NonNull::new_unchecked(l2_table);
                    munmap(self.munmap, InternalAllocKind::ShadowHeap, l2_table, l2_table_size)
                        .expect("failed to unmap block");
                }
            }
            let size_bytes = NonZero::new_unchecked(mem::size_of::<L1Array<T>>());
            munmap::<L1Array<T>>(
                self.munmap,
                InternalAllocKind::ShadowHeap,
                self.table,
                size_bytes,
            )
            .expect("failed to unmap block");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::hooks::DEFAULT_HOOKS;
    use crate::memory::AllocResult;

    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
    struct TestProv {
        value: u128,
    }

    static DEFAULT_TEST_PROV: TestProv = TestProv { value: 0 };

    #[test]
    fn test_indices() {
        let null_idx = TableIndex::new(0);
        let null_offset_idx = TableIndex::new(1);
        assert_eq!(null_idx, null_offset_idx);

        let next_prov_same_page: TableIndex = TableIndex::new(PTR_BYTES);
        assert_eq!(next_prov_same_page.l2_index, 1);

        let next_page: TableIndex = TableIndex::new(L2_LEN * PTR_BYTES);
        assert_eq!(next_page.l2_index, 0);
        assert_eq!(next_page.l1_index, 1);
    }

    #[test]
    fn test_shadow_heap_creation() {
        ShadowHeap::<TestProv>::new(&DEFAULT_HOOKS, &raw const DEFAULT_TEST_PROV)
            .expect("failed to unmap block");
    }

    #[test]
    fn test_load_null_prov() -> AllocResult<()> {
        let heap = ShadowHeap::<TestProv>::new(&DEFAULT_HOOKS, &raw const DEFAULT_TEST_PROV)?;
        let prov = unsafe { *heap.get_src(18) };
        assert_eq!(prov, DEFAULT_TEST_PROV);
        Ok(())
    }

    #[test]
    fn test_store_and_load_prov() -> AllocResult<()> {
        let heap = ShadowHeap::<TestProv>::new(&DEFAULT_HOOKS, &raw const DEFAULT_TEST_PROV)?;
        let test_prov = TestProv { value: 42 };
        // Use an address that will split into non-zero indices for both L1 and L2
        let addr = 0x1234_5678_1234_5678;
        unsafe {
            let dest = heap.get_dest(&DEFAULT_HOOKS, addr)?;
            *dest = test_prov;
        }
        unsafe {
            let loaded_prov = *heap.get_src(addr);
            assert_eq!(loaded_prov.value, test_prov.value);
        }
        Ok(())
    }

    #[test]
    fn clear() -> AllocResult<()> {
        let heap = ShadowHeap::<TestProv>::new(&DEFAULT_HOOKS, &raw const DEFAULT_TEST_PROV)?;
        let src_address: usize = 0;
        let prov = TestProv { value: 81 };

        let max = 40;

        for offset in 0..max {
            let offset_bytes = offset * PTR_BYTES;
            unsafe {
                let dest = heap.get_dest(&DEFAULT_HOOKS, src_address + offset_bytes)?;
                *dest = prov;
            }
        }

        heap.clear(src_address, max * PTR_BYTES);
        for offset in 0..max {
            let offset_bytes = offset * PTR_BYTES;
            let compare_prov = unsafe { *heap.get_src(src_address + offset_bytes) };
            assert_eq!(compare_prov, TestProv::default())
        }
        Ok(())
    }

    #[test]
    fn memcpy() -> AllocResult<()> {
        let heap = ShadowHeap::<TestProv>::new(&DEFAULT_HOOKS, &raw const DEFAULT_TEST_PROV)?;

        let max = 40;
        let halfmax = max / 2;
        let three_quarter_max = max - (max / 4);

        let src_address: usize = 0;
        let prov = TestProv { value: 81 };

        // offset the destination address so that we need to cross a page.
        let dst_address = (L2_LEN - (halfmax / 2)) * PTR_BYTES;

        for offset in 0..three_quarter_max {
            let offset_bytes = offset * PTR_BYTES;
            unsafe {
                *heap.get_dest(&DEFAULT_HOOKS, src_address + offset_bytes)? = prov;
            }
            let compare_prov = unsafe { *heap.get_src(src_address + offset_bytes) };
            assert_eq!(prov, compare_prov)
        }
        heap.memcpy(&DEFAULT_HOOKS, src_address, dst_address, max * PTR_BYTES).unwrap();

        for offset in 0..three_quarter_max {
            let offset_bytes = offset * PTR_BYTES;
            let compare_prov = unsafe { *heap.get_src(dst_address + offset_bytes) };
            assert_eq!(prov, compare_prov)
        }

        for offset in (three_quarter_max + 1)..max {
            let offset_bytes = offset * PTR_BYTES;
            let compare_prov = unsafe { *heap.get_src(dst_address + offset_bytes) };
            assert_eq!(compare_prov, TestProv::default())
        }
        Ok(())
    }

    #[test]
    fn smoke() -> AllocResult<()> {
        let heap = ShadowHeap::<TestProv>::new(&DEFAULT_HOOKS, &raw const DEFAULT_TEST_PROV)?;
        // Create test data
        const NUM_OPERATIONS: usize = 10;
        const BASE_ADDR: usize = 0x7FFF_FFFF_AA00;

        let test_values: Vec<TestProv> =
            (0..NUM_OPERATIONS).map(|i| TestProv { value: (i % 255) as u128 }).collect();

        // Use a properly aligned base address
        assert_eq!(BASE_ADDR % 8, 0);
        unsafe {
            for (i, test_value) in test_values.iter().enumerate().take(NUM_OPERATIONS) {
                let addr = BASE_ADDR + (i * 8);
                *heap.get_dest(&DEFAULT_HOOKS, addr)? = *test_value;
                let prov = *heap.get_src(addr);
                assert_eq!(prov.value, test_value.value);
            }

            for (i, test_value) in test_values.iter().enumerate().take(NUM_OPERATIONS) {
                let addr = BASE_ADDR + (i * 8);
                let prov = *heap.get_src(addr);
                assert_eq!(prov.value, test_value.value);
                *heap.get_dest(&DEFAULT_HOOKS, addr)? = *test_value;
            }
        }
        Ok(())
    }
}
