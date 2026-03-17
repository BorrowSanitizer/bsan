use std::thread;
use std::sync::atomic::AtomicPtr;


#[path = "../utils/bsan_extern.rs"]
#[macro_use]
mod bsan_debug;

/* 
fn print_provenance_info(addr: *const std::ffi::c_void) {
    unsafe {
        let shadow_prov_ptr = bsan_debug::__bsan_shadow_src(addr) as *const Provenance;
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
*/

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Provenance {
    pub bor_tag: u64,
    pub alloc_info: *mut std::ffi::c_void,
}
unsafe impl Send for Provenance {}
unsafe impl Sync for Provenance {}

macro_rules! get_provenance {
    ($val:expr, $tag:ident, $info:ident) => {
        let mut $tag: u64 = 0;
        let mut $info: *mut std::ffi::c_void = std::ptr::null_mut();
        unsafe {
            bsan_debug::__bsan_debug_get_provenance($val as *const std::ffi::c_void, &mut $tag, &mut $info);
        }
    };
}


/// Just a wrapper around raw pointers to make them Send and Sync when sending the hashmap across threads.
#[repr(transparent)]
#[derive(Eq, Hash, PartialEq)]
struct UnsafeSend<T>(*mut T);
unsafe impl<T> Send for UnsafeSend<T> {}
unsafe impl<T> Sync for UnsafeSend<T> {}

const NUM_THREADS: usize = 200;

fn main() {
    for &(store_ordering, load_ordering) in &[ 
        (std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst),
        (std::sync::atomic::Ordering::Release, std::sync::atomic::Ordering::Acquire),
        (std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed),
    ] {
        println!("Testing with store ordering: {:?}, load ordering: {:?}", store_ordering, load_ordering);
        store_and_load(store_ordering, load_ordering);
    }
}



fn store_and_load(store_ordering: std::sync::atomic::Ordering, load_ordering: std::sync::atomic::Ordering) {
    let values: [u32; NUM_THREADS] = std::array::from_fn(|i| (i + 1) as u32);

    let mut prov_map = std::collections::HashMap::<UnsafeSend<u32>, Provenance>::new();
    for i in 0..values.len() {
        let ptr = &values[i] as *const u32 as *mut u32; // Get a raw pointer to x
        get_provenance!(ptr, bor_tag, alloc_info);
        let prov = Provenance { bor_tag, alloc_info };
        println!("Storing pointer {:p} (value: {}) to prov_map with provenance: {:?}", ptr, unsafe {*ptr}, prov); 
        let inserted_ptr = UnsafeSend(ptr);
        prov_map.insert(inserted_ptr, prov);
    }


    let pointer_storage: AtomicPtr<u32> = AtomicPtr::new(std::ptr::null_mut());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(NUM_THREADS + prov_map.len()));

    thread::scope(|s| {
        for (ptr, _) in prov_map.iter() {
            let pointer_storage_ref = &pointer_storage;
            let barrier = &barrier;
            s.spawn(move || {
                barrier.wait(); // Increase the chance that loads and stores happen around the same time, making the test more likely to catch issues.
                pointer_storage_ref.store(ptr.0, store_ordering);
            });
        }

        for _ in 0..NUM_THREADS {
            let pointer_storage_ref = &pointer_storage;
            let prov_map_ref = &prov_map;
            let barrier = &barrier;
            s.spawn(move || {
                barrier.wait(); // Increase the chance that loads and stores happen around the same time, making the test more likely to catch issues.
                let loaded_ptr: *mut u32 = pointer_storage_ref.load(load_ordering);
                if !loaded_ptr.is_null() {     
                    get_provenance!(loaded_ptr, bor_tag, alloc_info);
                    let orignal_prov = prov_map_ref.get(&UnsafeSend(loaded_ptr)).unwrap();
                    assert_eq!(orignal_prov.bor_tag, bor_tag);
                    assert_eq!(orignal_prov.alloc_info, alloc_info);
                }
            });
        }
    });

    println!("Threads have joined successfully. Test ends here. BSAN should not have reported any issues if synchronization of provenance is working correctly.");
}
