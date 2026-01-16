#[cfg(test)]
mod tests {
    use core::sync::atomic::Ordering;

    use crate::*;

    fn with_init(unit_test: fn()) {
        unsafe { __bsan_internal_init() };
        unit_test();
        unsafe { __bsan_internal_deinit() };
    }

    fn with_heap_object(unit_test: fn(obj: *mut c_void, size: usize)) {
        let obj = unsafe { libc::malloc(64) };
        unit_test(obj, 64);
        unsafe { libc::free(obj) };
    }

    fn create_metadata(base_addr: *mut c_void, size: usize) -> Provenance {
        unsafe {
            let alloc_id = AllocId(__BSAN_ALLOC_ID_CTR.fetch_add(1, Ordering::Relaxed));
            let bor_tag = BorTag(__BSAN_BOR_TAG_CTR.fetch_add(1, Ordering::Relaxed));
            let alloc_info = __bsan_alloc(base_addr, size, alloc_id, bor_tag).as_ptr();
            Provenance { alloc_id, bor_tag, alloc_info }
        }
    }

    fn destroy_metadata(ptr: *mut c_void, prov: Provenance) {
        __bsan_dealloc(ptr, prov.alloc_id, prov.bor_tag, prov.alloc_info, false);
    }

    #[test]
    fn bsan_alloc_increasing_alloc_id() {
        with_init(|| {
            with_heap_object(|obj1, size1| {
                let prov1 = create_metadata(obj1, size1);
                assert_eq!(prov1.alloc_id, AllocId::min());
                with_heap_object(|obj2, size2| {
                    let prov2 = create_metadata(obj2, size2);
                    assert_eq!(prov2.alloc_id, AllocId(AllocId::min().get() + 1));
                    destroy_metadata(obj2, prov2);
                });
                destroy_metadata(obj1, prov1);
            });
        });
    }

    #[test]
    fn bsan_alloc_and_dealloc() {
        with_init(|| {
            with_heap_object(|obj, size| unsafe {
                let prov = create_metadata(obj, size);
                destroy_metadata(obj, prov);
                let alloc_metadata = &*prov.alloc_info;
                assert_eq!(alloc_metadata.alloc_id, AllocId::invalid());
            });
        })
    }

    #[test]
    #[should_panic]
    #[cfg(not(miri))]
    fn bsan_dealloc_detect_double_free() {
        with_init(|| {
            with_heap_object(|obj, size| {
                let prov = create_metadata(obj, size);
                destroy_metadata(obj, prov);
                destroy_metadata(obj, prov);
            })
        });
    }

    #[test]
    #[should_panic]
    #[cfg(not(miri))]
    fn bsan_dealloc_detect_invalid_free() {
        with_init(|| {
            with_heap_object(|obj, size| {
                let prov = create_metadata(obj, size);
                let mut modified_prov = prov;
                modified_prov.alloc_id = AllocId::new(99);
                destroy_metadata(obj, modified_prov);
            });
        })
    }

    #[test]
    fn bsan_read() {
        with_init(|| {
            with_heap_object(|obj: *mut c_void, size: usize| unsafe {
                let prov = create_metadata(obj, size);
                __bsan_read(obj, size, prov.alloc_id, prov.bor_tag, prov.alloc_info);
                destroy_metadata(obj, prov);
            });
        });
    }

    #[test]
    fn bsan_write() {
        with_init(|| {
            with_heap_object(|obj, size| unsafe {
                let prov = create_metadata(obj, size);
                __bsan_write(obj, size, prov.alloc_id, prov.bor_tag, prov.alloc_info);
                destroy_metadata(obj, prov);
            });
        });
    }
}
