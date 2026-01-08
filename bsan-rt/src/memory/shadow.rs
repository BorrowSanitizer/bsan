use alloc::vec::Vec;
use core::num::NonZero;
use core::ops::{BitAnd, Shr};
use core::ptr::NonNull;
use core::{mem, ptr};

use hashbrown::HashSet;
use spin::{Mutex, RwLock};

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
type L1Array<T> = [RwLock<*mut L2Array<T>>; L1_LEN];

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

#[repr(C)]
#[derive(Debug)]
pub struct ShadowHeap<T> {
    table: NonNull<L1Array<T>>,
    default: *const T,
    visited: Mutex<HashSet<NonNull<T>>>,
    l2_blocks: RwLock<Vec<usize>>,
}

unsafe impl<T> Sync for ShadowHeap<T> {}
unsafe impl<T> Send for ShadowHeap<T> {}

impl<T: Sized + Default + Copy> ShadowHeap<T> {
    /// We assume that `new` is only called during program initialization, so only by the main thread.
    /// So there should be no deadlock / synchronization issues.
    pub fn new(default: *const T) -> Self {
        unsafe {
            // RwLock is safe to assume initialized, since the pages returned by mmap are zeroed.
            // TODO: enforce this using an unsafe trait.
            let table = {
                let size_bytes = NonZero::new_unchecked(mem::size_of::<L1Array<T>>());
                mmap(size_bytes).cast::<L1Array<T>>()
            };
            Self {
                table,
                default,
                visited: Mutex::new(HashSet::new()),
                l2_blocks: RwLock::new(Vec::<usize>::new()),
            }
        }
    }

    #[inline]
    fn get_l2(&self, idx: TableIndex) -> Option<NonNull<L2Array<T>>> {
        unsafe {
            let l1_entry = &(*self.table.as_ptr())[idx.l1_index];
            let read_guard = l1_entry.read();
            let l2_page_ptr = *read_guard;
            NonNull::new(l2_page_ptr)
        }
    }

    fn ensure_l2(&self, idx: TableIndex) -> NonNull<L2Array<T>> {
        unsafe {
            let l1_entry = &(*self.table.as_ptr())[idx.l1_index];

            // Fast path: check with read lock (non-blocking for readers)
            let read_guard = l1_entry.upgradeable_read();
            let l2_ptr = *read_guard;
            if !l2_ptr.is_null() {
                return NonNull::new_unchecked(l2_ptr);
            }

            // Slow path: upgrade to write lock for mmap allocation
            // With an upgradable lock we don't need to double-check that l2_ptr is
            // still null because the lock prevents other writers.
            let mut write_guard = read_guard.upgrade();
            let size_bytes = NonZero::new_unchecked(mem::size_of::<T>() * L2_LEN);
            let l2_page = mmap(size_bytes).cast::<L2Array<T>>();

            *write_guard = l2_page.as_ptr();
            drop(write_guard); // release lock early and prevent deadlocks

            self.l2_blocks.write().push(idx.l1_index);
            l2_page
        }
    }

    pub fn clear(&self, dst: usize, num_bytes: usize, value: T) {
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
                    (*l2_dest.as_ptr())[dst_index.l2_index] = value;
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

    pub fn store_consecutive(&self, dst: usize, it: impl Iterator<Item = T>) {
        let table_idx = TableIndex::new(dst);
        for (prov_idx, prov) in it.enumerate() {
            let idx = table_idx.add(prov_idx);
            let l2_dest = self.ensure_l2(idx);
            unsafe {
                (*l2_dest.as_ptr())[idx.l2_index] = prov;
            }
        }
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
    pub fn memcpy(&self, src: usize, dst: usize, num_bytes: usize) {
        if num_bytes < PTR_BYTES {
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
                            T::default(), // FIXME: we should use *self.default here?
                        );
                    }
                }
                src_index = src_index.add(num_can_write);
                dst_index = dst_index.add(num_can_write);

                words_remaining -= num_can_write;
            }
        }
    }

    pub fn get_src(&self, addr: usize) -> *const T {
        let idx = TableIndex::new(addr);
        unsafe {
            self.get_l2(idx)
                .map(|l2_page| &raw const (*l2_page.as_ptr())[idx.l2_index])
                .unwrap_or(self.default)
        }
    }

    pub fn get_dest(&self, addr: usize) -> NonNull<T> {
        let idx = TableIndex::new(addr);
        unsafe {
            let l2_page = self.ensure_l2(idx);
            let ptr = &raw mut (*l2_page.as_ptr())[idx.l2_index];
            let ptr = NonNull::new_unchecked(ptr);
            self.visited.lock().insert(ptr);
            ptr
        }
    }
}

impl<T> Drop for ShadowHeap<T> {
    /// We assume that `drop()` is only called during program deinit, so only by the main thread.
    /// So there should be no deadlock / synchronization issues.
    fn drop(&mut self) {
        unsafe {
            // Free all L2 tables
            let mut l2_blocks_guard = self.l2_blocks.write();
            for i in l2_blocks_guard.drain(..) {
                let l1_entry = &(*self.table.as_ptr())[i];
                let mut l1_entry_guard = l1_entry.write();
                let l2_table = *l1_entry_guard;
                if !l2_table.is_null() {
                    let l2_table_size = NonZero::new_unchecked(mem::size_of::<T>() * L2_LEN);
                    let l2_table = NonNull::new_unchecked(l2_table);
                    munmap(l2_table, l2_table_size);
                    *l1_entry_guard = ptr::null_mut();
                }
            }
            // Free the L1 table (RwLocks will be dropped automatically)
            let size_bytes = NonZero::new_unchecked(mem::size_of::<L1Array<T>>());
            munmap::<L1Array<T>>(self.table, size_bytes);
        }
    }
}
/*
impl VisitTags for ShadowHeap<Provenance> {
    fn visit_tags(&self, tags: &mut HashSet<BorTag>) {
        let mut visited = self.visited.lock();
        visited
            .extract_if(|prov| {
                let tag = unsafe { prov.as_ref().bor_tag };
                if tag != BorTag::null() {
                    tags.insert(tag);
                }
                tag == BorTag::null()
            })
            .for_each(|_| {});
    }
}*/

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
        ShadowHeap::<TestProv>::new(&raw const DEFAULT_TEST_PROV);
    }

    #[test]
    fn test_load_null_prov() {
        let heap = ShadowHeap::<TestProv>::new(&raw const DEFAULT_TEST_PROV);
        let prov = unsafe { *heap.get_src(18) };
        assert_eq!(prov, DEFAULT_TEST_PROV);
    }

    #[test]
    fn test_store_and_load_prov() {
        let heap = ShadowHeap::<TestProv>::new(&raw const DEFAULT_TEST_PROV);
        let test_prov = TestProv { value: 42 };
        // Use an address that will split into non-zero indices for both L1 and L2
        let addr = 0x1234_5678_1234_5678;
        unsafe {
            let dest = heap.get_dest(addr);
            *dest.as_ptr() = test_prov;
        }
        unsafe {
            let loaded_prov = *heap.get_src(addr);
            assert_eq!(loaded_prov.value, test_prov.value);
        }
    }

    #[test]
    fn clear() {
        let heap = ShadowHeap::<TestProv>::new(&raw const DEFAULT_TEST_PROV);
        let src_address: usize = 0;
        let prov = TestProv { value: 81 };

        let max = 40;

        for offset in 0..max {
            let offset_bytes = offset * PTR_BYTES;
            unsafe {
                let dest = heap.get_dest(src_address + offset_bytes);
                *dest.as_ptr() = prov;
            }
        }

        heap.clear(src_address, max * PTR_BYTES, TestProv::default());
        for offset in 0..max {
            let offset_bytes = offset * PTR_BYTES;
            let compare_prov = unsafe { *heap.get_src(src_address + offset_bytes) };
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
                *heap.get_dest(src_address + offset_bytes).as_ptr() = prov;
            }
            let compare_prov = unsafe { *heap.get_src(src_address + offset_bytes) };
            assert_eq!(prov, compare_prov)
        }
        heap.memcpy(src_address, dst_address, max * PTR_BYTES);

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
    }

    #[bench]
    fn memcpy_bench(b: &mut test::Bencher) {
        let heap = ShadowHeap::<TestProv>::new(&raw const DEFAULT_TEST_PROV);
        b.iter(|| {
            inner_memcpy(&heap, 1024 * 1024);
        });
    }

    #[bench]
    fn create_memcpy_destroy(b: &mut test::Bencher) {
        b.iter(|| {
            let heap = ShadowHeap::<TestProv>::new(&raw const DEFAULT_TEST_PROV);
            inner_memcpy(&heap, 1024 * 1024);
        });
    }

    #[test]
    fn memcpy() {
        let heap = ShadowHeap::<TestProv>::new(&raw const DEFAULT_TEST_PROV);
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
        let heap = ShadowHeap::<TestProv>::new(&raw const DEFAULT_TEST_PROV);
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
                *heap.get_dest(addr).as_ptr() = *test_value;
                let prov = *heap.get_src(addr);
                assert_eq!(prov.value, test_value.value);
            }

            for (i, test_value) in test_values.iter().enumerate().take(NUM_OPERATIONS) {
                let addr = BASE_ADDR + (i * 8);
                let prov = *heap.get_src(addr);
                assert_eq!(prov.value, test_value.value);
                *heap.get_dest(addr).as_ptr() = *test_value;
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
        let test_prov = &DEFAULT_TEST_PROV as *const TestProv;
        let heap = Arc::new(ShadowHeap::<TestProv>::new(test_prov));
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
                let dest = heap.get_dest(addr);
                *dest.as_ptr() = test_value;

                let loaded: TestProv = *heap.get_src(addr);
                assert_eq!(loaded, test_value);
            }
        })
    }
}
