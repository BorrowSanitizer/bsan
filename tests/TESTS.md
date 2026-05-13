# Testing
BorrowSanitizer can detect two categories of undefined behavior.

* *Aliasing errors* - violations of Rust's Tree Borrows model
* *Baseline errors* - dangling pointers, accesses out-of-bounds, use-after-free errors, and other 
core memory safety violations that are prerequisite for detecting aliasing violations. 

Unit tests that fail are grouped under "aliasing" and "baseline" subdirectories, accordingly.

The `miri-tests` subdirectory contains the subset of Miri's test suite that
that either passes or has an aliasing or baseline form of undefined behavior when Miri
is in its default configuration, with Tree Borrows and symbolic alignment checking enabled.
Tests in the `should-pass` and `should-fail` directories currently have false 
positives or false negatives, or they time out. 

We have excluded most architecture-specific or Miri-specific test cases, focusing instead on
tests that exercise core components of Rust's provenance model.
