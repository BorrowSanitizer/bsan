#![cfg_attr(not(test), no_std)]
#![feature(cfg_select)]
#![allow(dead_code)]
#![feature(allocator_api)]

extern crate alloc;
mod foreign_access_skipping;
mod helpers;
pub mod perms;
mod range_map;
pub mod types;

pub use foreign_access_skipping::*;
pub use helpers::*;
pub use perms::*;
pub use range_map::*;
pub use types::*;
