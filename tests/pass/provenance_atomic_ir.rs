// LLVM Pass test: Verifies that provenance load/store operations generate
// proper 128-bit atomic instructions in the LLVM IR
//
// This test should be run as part of the LLVM pass test suite to verify:
// 1. Provenance values are represented as i128 in LLVM IR
// 2. Load operations use atomic load with proper alignment (16 bytes)
// 3. Store operations use atomic store with proper alignment
// 4. Tag and Info are extracted via bitshift operations
// 5. Concurrent access to provenance-carrying pointers works correctly
//
// To test manually, compile with: cargo-bsan and check the .ll output
// Expected IR pattern:
//   %combined = load atomic i128, ptr %prov_addr monotonic, align 16
//   %tag = trunc i128 %combined to i64
//   %info_shifted = lshr i128 %combined, 64
//   %info = trunc i128 %info_shifted to i64

use std::mem::MaybeUninit;
use std::thread;
use std::sync::atomic::AtomicPtr;


#[path = "../utils/bsan_extern.rs"]
mod bsanutils;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct Provenance {
    bor_tag: u64,
    alloc_info: *mut std::ffi::c_void,
}
unsafe impl Send for Provenance {}
unsafe impl Sync for Provenance {}


struct Node {
    value: i32,
    next: Option<Box<Node>>,
}

fn print_provenance_info(addr: *const std::ffi::c_void) {
    unsafe {
        let shadow_prov_ptr = bsanutils::__bsan_shadow_src(addr) as *const Provenance;
        if !shadow_prov_ptr.is_null() {
            let prov = *shadow_prov_ptr;
            println!("Provenance for address {:p}:", addr);
            println!("  Tag: {}", prov.bor_tag);
            println!("  Info: {:p}", prov.alloc_info);
        } else {
            println!("No provenance found for address {:p}", addr);
        }
    }
}


#[derive(Eq, Hash, PartialEq)]
struct UnsafeSend<T>(*mut T);
unsafe impl<T> Send for UnsafeSend<T> {}
unsafe impl<T> Sync for UnsafeSend<T> {}


fn main() {
    bla()
}

fn bla() {
    const NUM_THREADS: u32 = 8;

    // iterate over the number of threads and       map to a hashmap of Pointer address to provenance info
    let mut prov_map = std::collections::HashMap::new();
    for i in 0..NUM_THREADS {
        let ptr: UnsafeSend<u32> = UnsafeSend(Box::into_raw(Box::new(i))); // Create a pointer to a new value
        let mut bor_tag: MaybeUninit<u64> = MaybeUninit::uninit();  
        let mut alloc_info: MaybeUninit<*mut std::ffi::c_void> = MaybeUninit::uninit();
        unsafe {
            bsanutils::__bsan_debug_get_provenance(&*ptr.0 as *const _ as *const std::ffi::c_void, bor_tag.as_mut_ptr(), alloc_info.as_mut_ptr());
            bsanutils::__bsan_debug_print(&*ptr.0 as *const _ as *mut u8);
        }
        let prov = Provenance {
            bor_tag: unsafe { bor_tag.assume_init() },
            alloc_info: unsafe { alloc_info.assume_init() },
        };
        println!("Pointer {:p} (value: {}) has provenance: {:?}", ptr.0, unsafe {*ptr.0}, prov);
        prov_map.insert(ptr, prov);
    }


    let pointer_storage: AtomicPtr<u32> = AtomicPtr::new(std::ptr::null_mut());

    thread::scope(|s| {
        for (ptr, _) in prov_map.iter() {
            let ptr = UnsafeSend(&*ptr as *const _ as *mut u32); // Convert to raw pointer for Send
            let pointer_storage_ref = &pointer_storage;
            s.spawn(move || {
                pointer_storage_ref.store(ptr.0, std::sync::atomic::Ordering::SeqCst);
            });
        }

        for _ in 0..NUM_THREADS {
            let pointer_storage_ref = &pointer_storage;
            let prov_map_ref = &prov_map;
            s.spawn(move || {
                let loaded_ptr = pointer_storage_ref.load(std::sync::atomic::Ordering::SeqCst);
                if !loaded_ptr.is_null() {
                    unsafe {
                        println!("Loaded pointer value: {}", *loaded_ptr);
                    }
                    let ptr_storage_addr = pointer_storage_ref as *const AtomicPtr<u32> as *const *mut u32;
                    let loaded_provenance: Provenance = unsafe { *(bsanutils::__bsan_shadow_src(ptr_storage_addr as *const std::ffi::c_void) as *const Provenance) };
                    
                    let orignal_prov = prov_map_ref.get(&UnsafeSend(loaded_ptr)).unwrap();

                    assert_eq!(orignal_prov.bor_tag, loaded_provenance.bor_tag);
                    assert_eq!(orignal_prov.alloc_info, loaded_provenance.alloc_info);
                }
            });
        }
    });
}
