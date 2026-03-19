use std::thread;
use std::sync::atomic::AtomicPtr;


#[path = "../utils/bsan_extern.rs"]
#[macro_use]
mod bsanutils;

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


#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Provenance {
    pub bor_tag: u64,
    pub alloc_info: *mut std::ffi::c_void,
}

macro_rules! get_provenance {
    ($val:expr) => {{
        let mut bor_tag: u64 = 0;
        let mut alloc_info: *mut std::ffi::c_void = std::ptr::null_mut();
        unsafe {
            let ptr = $val;
            bsanutils::__bsan_debug_get_provenance($val as *const std::ffi::c_void, &mut bor_tag, &mut alloc_info);
        }
        Provenance {
            bor_tag,
            alloc_info,
        }
    }};
}


/// Just a wrapper around raw pointers to make them Send and Sync when sending the hashmap across threads.
#[repr(transparent)]
#[derive(Eq, Hash, PartialEq)]
struct UnsafeSend<T>(*mut T);
unsafe impl<T> Send for UnsafeSend<T> {}
unsafe impl<T> Sync for UnsafeSend<T> {}


fn main() {
    bla()
}

fn bla() {
    const NUM_THREADS: usize = 8;
    const NUM_POINTERS: usize = 8;
    let values: [u32; NUM_POINTERS] = [0, 1, 2, 3, 4, 5, 6, 7];

    let mut prov_map = std::collections::HashMap::<UnsafeSend<u32>, Provenance>::new();
    for i in 0..NUM_POINTERS {
        let ptr = &values[i] as *const u32 as *mut u32; // Get a raw pointer to x
        let prov = get_provenance!(ptr);
        println!("Pointer {:p} (value: {}) has provenance: {:?}", ptr, unsafe {*ptr}, prov);
        
        let inserted_ptr = UnsafeSend(ptr);
        println!("Storing provenance for pointer {:p} in map", inserted_ptr.0);
        prov_map.insert(inserted_ptr, prov);
    }


    let pointer_storage: AtomicPtr<u32> = AtomicPtr::new(std::ptr::null_mut());

    thread::scope(|s| {
        for (ptr, _) in prov_map.iter() {
            let pointer_storage_ref = &pointer_storage;
            s.spawn(move || {
                let prov = get_provenance!(ptr.0);
                println!("Atomic Pointer storage: storing pointer {:p} with Provenance: {:?}", ptr.0, prov);
                pointer_storage_ref.store(ptr.0, std::sync::atomic::Ordering::SeqCst);
            });
        }

        for i in 0..NUM_THREADS {
            let pointer_storage_ref = &pointer_storage;
            let prov_map_ref = &prov_map;
            s.spawn(move || {
                // Check AtomicPtr shadow before loading
                let storage_addr = pointer_storage_ref as *const AtomicPtr<u32> as *const std::ffi::c_void;
                unsafe {
                    let shadow_ptr = bsanutils::__bsan_shadow_src(storage_addr) as *const Provenance;
                    if !shadow_ptr.is_null() {
                        let shadow_prov = *shadow_ptr;
                        println!("Thread {i} before load: AtomicPtr shadow contains: {:?}", shadow_prov);
                    } else {
                        println!("Thread {i} before load: AtomicPtr shadow is null!");
                    }
                }
                
                let loaded_ptr: *mut u32 = pointer_storage_ref.load(std::sync::atomic::Ordering::SeqCst);
                if !loaded_ptr.is_null() {
                    // Check loaded_ptr's shadow memory directly
                    unsafe {
                        let loaded_ptr_shadow_addr = &loaded_ptr as *const _ as *const std::ffi::c_void;
                        let loaded_ptr_shadow = bsanutils::__bsan_shadow_src(loaded_ptr_shadow_addr) as *const Provenance;
                        if !loaded_ptr_shadow.is_null() {
                            let shadow_prov = *loaded_ptr_shadow;
                            println!("Thread {i} loaded_ptr variable's shadow contains: {:?}", shadow_prov);
                        } else {
                            println!("Thread {i} loaded_ptr variable's shadow is null!");
                        }
                    }
                    
                    let loaded_ptr_prov = get_provenance!(loaded_ptr);
                    unsafe {
                        println!("Thread {i} loading pointer {:p} (value: {}) with Provenance: {:?}", loaded_ptr, *loaded_ptr, loaded_ptr_prov);
                    }
                    
                    let orignal_prov = prov_map_ref.get(&UnsafeSend(loaded_ptr)).unwrap();

                    assert_eq!(orignal_prov.bor_tag, loaded_ptr_prov.bor_tag);
                    assert_eq!(orignal_prov.alloc_info, loaded_ptr_prov.alloc_info);
                }
            });
        }
    });
}
