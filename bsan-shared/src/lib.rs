#![cfg_attr(not(test), no_std)]
#![allow(dead_code)]
#![feature(allocator_api)]

extern crate alloc;

pub mod foreign_access_skipping;
pub mod helpers;
pub mod perms;
pub mod range_map;
pub mod types;
