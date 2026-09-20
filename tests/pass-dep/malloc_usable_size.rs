use libc::{malloc, free, malloc_usable_size};


fn main() {
    unsafe {
        let ptr = malloc(12);
        assert!(malloc_usable_size(ptr) > 0);
        free(ptr);
    };
}
