#![allow(dead_code)]
#![allow(unused_imports)]

unsafe extern "C" {
    /// Prints the size of the tree associated with the pointer.
    pub unsafe fn __bsan_debug_tree_size(ptr: *mut u8);
    /// Prints the borrow state (print's the tree)
    pub unsafe fn __bsan_debug_print_borrow_state(ptr: *mut u8);
    /// Takes a global "snapshot" of the state of the tree.
    pub unsafe fn __bsan_debug_snapshot(ptr: *mut u8);
    /// Prints the difference between the current tree and its previous
    /// snapshot, if one exists.
    pub unsafe fn __bsan_debug_print_diff(ptr: *mut u8);
}

#[macro_export]
macro_rules! tree {
    ($val:expr) => {
        #[allow(unused)]
        unsafe {
            let ptr: *mut u8 = unsafe { core::mem::transmute($val) };
            utils::__bsan_debug_print_borrow_state(ptr);
        }
    };
}


#[macro_export]
macro_rules! snapshot {
    ($val:expr) => {
        #[allow(unused)]
        unsafe {
            let ptr: *mut u8 = unsafe { core::mem::transmute($val) };
            utils::__bsan_debug_snapshot(ptr);
        }
    };
}

#[macro_export]
macro_rules! diff {
    ($val:expr) => {
        #[allow(unused)]
        unsafe {
            let ptr: *mut u8 = unsafe { core::mem::transmute($val) };
            utils::__bsan_debug_print_diff(ptr);
        }
    };
}


#[macro_export]
macro_rules! nodes {
    ($val:expr) => {
        #[allow(unused)]
        unsafe {
            let ptr: *mut u8 = unsafe { core::mem::transmute($val) };
            utils::__bsan_debug_tree_size(ptr);
        }
    };
}