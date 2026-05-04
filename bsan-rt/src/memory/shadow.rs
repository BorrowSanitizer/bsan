use alloc::vec::Vec;
use core::mem::MaybeUninit;
use core::num::NonZero;
use core::ops::{BitAnd, Shr};
use core::ptr::NonNull;
use core::{mem, ptr};

use spin::RwLock;

use super::{mmap, munmap};

/// Different targets have a different number
/// of significant bits in their pointer representation.
/// On 32-bit platforms, all 32-bits are addressable. Most
/// 64-bit platforms only use 48-bits. Following the LLVM Project,
/// we hard-code these values based on the underlying architecture.
/// Most if not all 64 bit architectures use 48-bits. However, the
/// Armv8-A spec allows addressing 52 or 56 bits as well. No processors
/// implement this yet, though, so we can use target_pointer_width.
#[cfg(target_pointer_width = "64")]
const VA_BITS: u32 = 48;

#[cfg(target_pointer_width = "32")]
const VA_BITS: u32 = 32;

#[cfg(target_pointer_width = "16")]
const VA_BITS: u32 = 16;

// The power of the number of bytes in a pointer
const PTR_BYTES: usize = mem::size_of::<usize>();
const PTR_BYTES_POWER: u32 = PTR_BYTES.ilog2();

// The number of addressable, word-aligned, pointer-sized chunks
const NUM_ADDR_CHUNKS: u32 = VA_BITS - PTR_BYTES_POWER;

// We have 2^L2_POWER entries in the second level of the page table
// Adding 1 ensures that we have more second-level entries than first
// level entries if the number of addressable chunks is odd.
const L2_POWER: u32 = NUM_ADDR_CHUNKS.strict_add(1).strict_div(2);

// We have 2^L1_POWER entries in the first level of the page table
const L1_POWER: u32 = NUM_ADDR_CHUNKS.strict_div(2);

// The number of entries in the second level of the page table
const L2_LEN: usize = 2_usize.pow(L2_POWER);

// The number of entries in the first level of the page table
const L1_LEN: usize = 2_usize.pow(L1_POWER);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableIndex {
    l1_index: usize,
    l2_index: usize,
}

use bytemuck::Zeroable;
struct ZeroableRwLock<T: Zeroable> {
    pub inner: RwLock<T>,
}
unsafe impl<T: Zeroable> Zeroable for ZeroableRwLock<T> {}

type L1Entry<T> = ZeroableRwLock<Option<NonNull<L2Array<T>>>>;
type L2Entry<T> = T;
type L2Array<T> = [L2Entry<T>; L2_LEN];
type L1Array<T> = [L1Entry<T>; L1_LEN];

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
        let l1_index = self.l1_index + (element_offset / L2_LEN) % L1_LEN;
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

/// A two-level shadow memory heap implementation for tracking metadata about heap allocations.
///
/// This structure uses a sparse two-level page table to efficiently map memory addresses to
/// shadow values of type `T`. It minimizes memory overhead by only allocating L2 pages on demand.
/// Allocation is done via `mmap`. Therefore `T` must be `Sized` to ensure that we can calculate
/// the size of the allocated pages.
#[repr(C)]
#[derive(Debug)]
pub struct ShadowHeap<T> {
    /// Non-null pointer to the L1 page table array, allocated via mmap at initialization.
    table: NonNull<L1Array<T>>,
    /// Thread-safe list of allocated L2 page indices, used for cleanup and iteration over populated shadow memory regions.
    l2_blocks: RwLock<Vec<usize>>,
}

unsafe impl<T> Sync for ShadowHeap<T> {}
unsafe impl<T> Send for ShadowHeap<T> {}

impl<T: Sized> ShadowHeap<T> {
    // Size of L1 and L2 tables in bytes
    // The check for non-zero is done at compile time, hence the unwrap is safe.
    const L1_SIZE: NonZero<usize> = NonZero::new(mem::size_of::<L1Array<T>>()).unwrap();
    const L2_SIZE: NonZero<usize> = NonZero::new(mem::size_of::<T>() * L2_LEN).unwrap();
}

impl<T: Sized + Copy> ShadowHeap<T> {
    /// We assume that `new` is only called during program initialization, so only by the main thread.
    /// So there should be no deadlock / synchronization issues.
    pub fn new() -> Self {
        let table = mmap(Self::L1_SIZE).cast::<L1Array<T>>();
        // We can skip initialzation of each L1Entry because mmap returns a zeroed page and
        // we use ZeroableRwLock which is zero-initialized as RwLock::new(None)
        Self { table, l2_blocks: RwLock::new(Vec::<usize>::new()) }
    }

    #[inline]
    fn get_l2(&self, idx: TableIndex) -> Option<NonNull<L2Array<T>>> {
        // SAFETY: `self.table` should always be a valid pointer to an mmap'd L1Array
        let l1_entry = unsafe { &(*self.table.as_ptr())[idx.l1_index] };

        let read_guard = l1_entry.inner.read();
        *read_guard
    }

    fn ensure_l2(&self, idx: TableIndex) -> NonNull<L2Array<T>> {
        // SAFETY: `self.table` should always be a valid pointer to an mmap'd L1Array
        let l1_entry = unsafe { &(*self.table.as_ptr())[idx.l1_index] };

        // Fast path: check with read lock (non-blocking for readers)
        let read_guard = l1_entry.inner.upgradeable_read();
        let l2_ptr = *read_guard;
        if let Some(l2_ptr) = l2_ptr {
            return l2_ptr;
        }

        // Slow path: upgrade to write lock for mmap allocation
        // With an upgradeable lock we don't need to double-check that l2_ptr is still None because the lock prevents other writers.
        let mut write_guard = read_guard.upgrade();
        let l2_page = mmap(Self::L2_SIZE).cast::<L2Array<T>>();

        *write_guard = Some(l2_page);
        drop(write_guard); // release lock early and prevent deadlocks

        self.l2_blocks.write().push(idx.l1_index);
        l2_page
    }

    pub fn clear(&self, dst: usize, num_bytes: usize) {
        // We allow writing partial provenance values here, because if a pointer
        // is partially overwritten, then it should become invalid.
        let mut dst_index = TableIndex::new(dst);

        // Likewise, we want to round *up* to the nearest provenance value.
        #[cfg(target_endian = "little")]
        let mut prov_remaining = num_bytes.next_multiple_of(PTR_BYTES).shr(PTR_BYTES_POWER);
        #[cfg(target_endian = "big")]
        let mut prov_remaining = num_bytes.next_multiple_of(PTR_BYTES).shl(PTR_BYTES_POWER);

        while prov_remaining > 0 {
            if let Some(l2_dest) = self.get_l2(dst_index) {
                unsafe {
                    (*l2_dest.as_ptr())[dst_index.l2_index] =
                        MaybeUninit::<T>::zeroed().assume_init();
                }
                dst_index = dst_index.add(1);
                prov_remaining -= 1;
            } else {
                let num_remaining = dst_index.num_remaining_in_page();
                if num_remaining < prov_remaining {
                    prov_remaining -= num_remaining;
                } else {
                    break;
                }
            }
        }
    }

    /// Copy provenance values within a given range from the source to the destination.
    pub fn memcpy(&self, dst: usize, src: usize, num_bytes: usize) {
        if num_bytes < PTR_BYTES || src == dst {
            return;
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
                let l2_table_dst: NonNull<[T; L2_LEN]> = self.ensure_l2(dst_index);

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
                            MaybeUninit::<T>::zeroed().assume_init(),
                        );
                    }
                }
                src_index = src_index.add(num_can_write);
                dst_index = dst_index.add(num_can_write);

                words_remaining -= num_can_write;
            }
        }
    }

    pub fn get(&self, addr: usize) -> NonNull<T> {
        let idx = TableIndex::new(addr);
        unsafe {
            let l2_page = self.ensure_l2(idx);
            let ptr = &raw mut (*l2_page.as_ptr())[idx.l2_index];
            NonNull::new_unchecked(ptr)
        }
    }
}

impl<T> Drop for ShadowHeap<T> {
    /// We assume that `drop()` is only called during program deinit, so only by the main thread.
    /// So there should be no deadlock / synchronization issues.
    fn drop(&mut self) {
        // Free all L2 tables
        let mut l2_blocks_guard = self.l2_blocks.write();
        for i in l2_blocks_guard.drain(..) {
            // SAFETY: `self.table` should always be a valid pointer to an mmap'd L1Array
            let l1_entry = unsafe { &(*self.table.as_ptr())[i] };
            let mut l1_entry_guard = l1_entry.inner.write();
            let l2_table = *l1_entry_guard;
            if let Some(l2_table) = l2_table {
                unsafe { munmap(l2_table, Self::L2_SIZE) }
                *l1_entry_guard = None;
            }
        }
        // Free the L1 table (RwLocks will be dropped automatically)
        unsafe { munmap::<L1Array<T>>(self.table, Self::L1_SIZE) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate test;

    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
    struct TestProv {
        value: u128,
    }

    static DEFAULT_TEST_PROV: TestProv = TestProv { value: 0 };

    #[test]
    fn assert_rwlock_zero_init_valid() {
        use core::mem;
        let zeroed: L1Entry<crate::Provenance> = unsafe { mem::zeroed() };
        let explicit: L1Entry<crate::Provenance> = ZeroableRwLock { inner: RwLock::new(None) };

        // Compare byte representation
        let zeroed_bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(&zeroed as *const _ as *const u8, mem::size_of_val(&zeroed))
        };
        let explicit_bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(
                &explicit as *const _ as *const u8,
                mem::size_of_val(&explicit),
            )
        };

        assert_eq!(
            zeroed_bytes, explicit_bytes,
            "an L1 entry implicitly zero-initialized (by mmap) should be identical to \
            an L1 entry explicitly initialized as ZeroableRwLock {{ inner: RwLock::new(None) }}"
        );
    }

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
        ShadowHeap::<TestProv>::new();
    }

    #[test]
    fn test_load_null_prov() {
        let heap = ShadowHeap::<TestProv>::new();
        let prov = unsafe { heap.get(18).read() };
        assert_eq!(prov, DEFAULT_TEST_PROV);
    }

    #[test]
    fn test_store_and_load_prov() {
        let heap = ShadowHeap::<TestProv>::new();
        let test_prov = TestProv { value: 42 };
        // Use an address that will split into non-zero indices for both L1 and L2
        let addr = 0x1234_5678_1234_5678;
        unsafe {
            let dest = heap.get(addr);
            *dest.as_ptr() = test_prov;
        }
        unsafe {
            let loaded_prov = heap.get(addr).read();
            assert_eq!(loaded_prov.value, test_prov.value);
        }
    }

    #[test]
    fn clear() {
        let heap = ShadowHeap::<TestProv>::new();
        let src_address: usize = 0;
        let prov = TestProv { value: 81 };

        let max = 40;

        for offset in 0..max {
            let offset_bytes = offset * PTR_BYTES;
            unsafe {
                let dest = heap.get(src_address + offset_bytes);
                *dest.as_ptr() = prov;
            }
        }

        heap.clear(src_address, max * PTR_BYTES);
        for offset in 0..max {
            let offset_bytes = offset * PTR_BYTES;
            let compare_prov = unsafe { heap.get(src_address + offset_bytes).read() };
            assert_eq!(compare_prov, TestProv::default())
        }
    }

    fn inner_memcpy(heap: &ShadowHeap<TestProv>, max: usize) {
        let halfmax = max / 2;
        let three_quarter_max = max - (max / 4);

        let src_address: usize = 0;
        let prov = TestProv { value: 81 };

        // offset the destination address so that we need to cross a page.
        let dst_address = (L2_LEN - (halfmax / 2)) * PTR_BYTES;

        for offset in 0..three_quarter_max {
            let offset_bytes = offset * PTR_BYTES;
            unsafe {
                *heap.get(src_address + offset_bytes).as_ptr() = prov;
            }
            let compare_prov = unsafe { heap.get(src_address + offset_bytes).read() };
            assert_eq!(prov, compare_prov)
        }
        heap.memcpy(dst_address, src_address, max * PTR_BYTES);

        for offset in 0..three_quarter_max {
            let offset_bytes = offset * PTR_BYTES;
            let compare_prov = unsafe { heap.get(dst_address + offset_bytes).read() };
            assert_eq!(prov, compare_prov)
        }

        for offset in (three_quarter_max + 1)..max {
            let offset_bytes = offset * PTR_BYTES;
            let compare_prov = unsafe { heap.get(dst_address + offset_bytes).read() };
            assert_eq!(compare_prov, TestProv::default())
        }
    }

    #[bench]
    fn memcpy_bench(b: &mut test::Bencher) {
        let heap = ShadowHeap::<TestProv>::new();
        b.iter(|| {
            inner_memcpy(&heap, 1024 * 1024);
        });
    }

    #[bench]
    fn create_memcpy_destroy(b: &mut test::Bencher) {
        b.iter(|| {
            let heap = ShadowHeap::<TestProv>::new();
            inner_memcpy(&heap, 1024 * 1024);
        });
    }

    #[test]
    fn memcpy() {
        let heap = ShadowHeap::<TestProv>::new();
        inner_memcpy(&heap, 40)
    }

    #[test]
    fn index_arithmetic() {
        let root = TableIndex { l1_index: 256, l2_index: 1024 };
        let add_one = root.add(1);
        assert!(add_one.l1_index == root.l1_index);
        assert!(add_one.l2_index == root.l2_index + 1);
        assert!(add_one == root.add(2).sub(1));

        let sub_one = root.sub(1);
        assert!(sub_one == root.sub(2).add(1));
    }
    #[test]
    fn smoke() {
        let heap = ShadowHeap::<TestProv>::new();
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
                *heap.get(addr).as_ptr() = *test_value;
                let prov = heap.get(addr).read();
                assert_eq!(prov.value, test_value.value);
            }

            for (i, test_value) in test_values.iter().enumerate().take(NUM_OPERATIONS) {
                let addr = BASE_ADDR + (i * 8);
                let prov = heap.get(addr).read();
                assert_eq!(prov.value, test_value.value);
                *heap.get(addr).as_ptr() = *test_value;
            }
        }
    }

    fn with_threads<F: Fn(u32) + Send + Sync + 'static>(num_threads: u32, test_fn: F) {
        use std::sync::Arc;
        use std::thread;

        let mut handles = vec![];
        let test_fn = Arc::new(test_fn);

        for thread_counter in 0..num_threads {
            let test_fn = Arc::clone(&test_fn);
            let handle = thread::spawn(move || {
                test_fn(thread_counter);
            });
            handles.push(handle);
        }

        for (i, handle) in handles.into_iter().enumerate() {
            handle.join().unwrap_or_else(|_| panic!("Thread {} panicked", i));
        }
    }

    #[test]
    fn concurrent_l2_allocation_same_entry() {
        use std::sync::Arc;
        let heap = Arc::new(ShadowHeap::<TestProv>::new());
        // Use the same L1 index to maximize collision probability
        const BASE_ADDR: usize = 0x1000_0000;
        const NUM_THREADS: u32 = 16;
        let barrier = Arc::new(std::sync::Barrier::new(NUM_THREADS as usize));

        with_threads(NUM_THREADS, move |thread_id| {
            let aligned_offset = thread_id as usize * PTR_BYTES;
            let addr = BASE_ADDR + aligned_offset;
            let test_value = TestProv { value: thread_id as u128 };

            // increase probability of collision
            barrier.wait();

            unsafe {
                let dest = heap.get(addr);
                *dest.as_ptr() = test_value;

                let loaded: TestProv = heap.get(addr).read();
                assert_eq!(loaded, test_value);
            }
        })
    }

    /// Check for noticing if we increase the size of L1Entry during refactoring
    #[test]
    fn check_l1_entry_size() {
        type OldL2Array<T> = [T; L2_LEN];
        type OldL1Entry<T> = RwLock<*mut OldL2Array<T>>;
        // We have a RwLock<T> containing an AtomicUsize lock (8 bytes on 64-bit systems) + UnsafeCell<T> where T is a pointer (8 bytes on 64-bit systems) to an L2Array.
        use crate::Provenance;
        const _: () = assert!(size_of::<OldL1Entry<Provenance>>() == 16);
        const _: () =
            assert!(size_of::<L1Entry<Provenance>>() <= size_of::<OldL1Entry<Provenance>>());
    }
}