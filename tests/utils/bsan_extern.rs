// Each of these functions is transformed by the LLVM pass
// into corresponding calls to the runtime.
#[allow(unused)]
unsafe extern "C" {
    /// Asserts that a pointer's provenance value is null.
    pub unsafe fn __bsan_debug_assert_null(ptr: *mut u8);
    /// Asserts that a pointer's provenance value is wildcard.
    pub unsafe fn __bsan_debug_assert_wildcard(ptr: *mut u8);
    /// Asserts that a pointer has valid provenance.
    pub unsafe fn __bsan_debug_assert_valid(ptr: *mut u8);
    /// Asserts that a pointer has invalid provenance.
    pub unsafe fn __bsan_debug_assert_invalid(ptr: *mut u8);
    /// Prints debug information about a pointer's provenance.
    pub unsafe fn __bsan_debug_print(ptr: *mut u8);
    /// Prints the borrow state (print's the tree)
    pub unsafe fn __bsan_debug_print_borrow_state(ptr: *mut u8);
    /// Triggers garbage collection for the allocation associated with the pointer.
    pub unsafe fn __bsan_debug_gc(ptr: *mut u8);
    /// Prints the size of the tree associated with the pointer.
    pub unsafe fn __bsan_debug_tree_size(ptr: *mut u8);
    /// Retrieves the provenance metadata for the ptr.
    pub unsafe fn __bsan_debug_get_provenance(ptr: *const std::ffi::c_void, prov: *mut Provenance); 
    /// Returns the shadow memory location for an address
    pub unsafe fn __bsan_shadow_src(addr: *const std::ffi::c_void) -> *const std::ffi::c_void;
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Provenance {
    pub bor_tag: u64,
    pub alloc_info: *mut std::ffi::c_void,
}
unsafe impl Send for Provenance {}
unsafe impl Sync for Provenance {}


#[macro_export]
macro_rules! assert_prov_null {
    ($val:expr) => {
        unsafe {
            let ptr: *mut u8 = unsafe { ::core::mem::transmute($val) };
            bsan_debug::__bsan_debug_assert_null(ptr);
        }
    };
}

#[macro_export]
macro_rules! assert_prov_wildcard {
    ($val:expr) => {
        unsafe {
            let ptr: *mut u8 = unsafe { ::core::mem::transmute($val) };
            bsan_debug::__bsan_debug_assert_wildcard(ptr);
        }
    };
}

#[macro_export]
macro_rules! assert_prov_valid {
    ($val:expr) => {
        unsafe {
            let ptr: *mut u8 = unsafe { ::core::mem::transmute($val) };
            bsan_debug::__bsan_debug_assert_valid(ptr);
        }
    };
}

#[macro_export]
macro_rules! assert_prov_invalid {
    ($val:expr) => {
        unsafe {
            let ptr: *mut u8 = unsafe { ::core::mem::transmute($val) };
            bsan_debug::__bsan_debug_assert_invalid(ptr);
        }
    };
}

#[macro_export]
macro_rules! debug_prov {
    ($val:expr) => {
        unsafe {
            let ptr: *mut u8 = unsafe { ::core::mem::transmute($val) };
            bsan_debug::__bsan_debug_print(ptr);
        }
    };
}
