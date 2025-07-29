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
}

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
