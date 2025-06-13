pub(super) mod tree_borrows_wrapper {
    use core::ffi::c_void;
    pub type BorrowTag = u64;
    use alloc::boxed::Box;

    use log::debug;

    #[derive(Debug)]
    pub enum TreeBorrowsError {
        InvalidAccess,
    }

    #[derive(Debug)]
    pub struct Tree {}
    impl Tree {
        pub fn new(object_address: *const c_void, alloc_size: usize) -> Self {
            Self {}
        }

        pub fn get_root_borrow_tag(&self) -> BorrowTag {
            0
        }

        pub fn deallocate(
            &mut self,
            object_address: *const c_void,
            borrow_tag: BorrowTag,
        ) -> Result<(), TreeBorrowsError> {
            debug!( "Invalidating tree for object allocation at {object_address:p} with borrow tag {borrow_tag}");
            Ok(())
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            debug!("Dropping Tree");
        }
    }
}
