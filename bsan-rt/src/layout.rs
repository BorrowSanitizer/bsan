//! A parser for BorrowSanitizer's layout description format.
//!
//! In its default configuration, `-Zcodegen-emit-retag` will emit retag
//! calls that carry pointers to contant arrays of integers, describing which
//! ranges within the layout of a type are interior mutable (covered by an
//! `UnsafeCell`) or `!Unpin`.
//!
//! A naive encoding would emit this as a list of pairs of integers, merging
//! adjacent ranges. However, this ends up being massively inefficient for arrays
//! of types that only partially satisfy the predicate of the array. For example,
//! `[(Cell<u8>, u8); N]` requires emitting N pairs of (size, offset) to describe
//! that the first byte of each element is interior mutable.
//!
//! Instead, we use a straightforward compression encoding. By default we use
//! the naive encoding. However, when we encounter an array of partially covered
//! elements, we emit a special "repeat" instruction, followed by the ranges covered
//! by a single element. Go uses a similar encoding to describe where pointers live
//! within the layout of types that need to be visited by the garbage collector
//! (see https://go.dev/src/cmd/internal/gcprog/gcprog.go)
//!
//! This could be compressed further. For instance, a struct with identical fields
//! would still emit ranges for each field. Another option would be to use a bitmap
//! to describe the layout of structs with less than `sizeof::<T>()` bytes, where `T`
//! is some unsigned integer. This would only be worthwhile if there ends up being
//! a significant performance / resource use impact, which has yet to be seen.
use alloc::vec::Vec;
use core::mem;
use core::ptr::NonNull;

use crate::helpers::Size;

// Commands to describe individual "segments" of the compressed layout.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum LayoutCommand {
    // The next segment includes a nonzero `u64` count, followed by
    // that number of (offset, size) ranges.
    Ranges { count: u64 },
    // The next segment includes the stride, a nonzero number of
    // iterations, and a number of commands that should be repeated
    // for that count.
    Repeat { stride: Size, count: u64, num_cmds: u64 },
}

/// Integer tags indicating that the next series of bytes
/// is a particular [`LayoutCommand`].
#[repr(u64)]
#[allow(unused)]
enum LayoutCommandTag {
    /// The end of the array.
    End = 0,
    /// The next bytes are a [`LayoutCommand::Ranges`]
    Ranges = 1,
    /// The next bytes are a [`LayoutCommand::Repeat`]
    Repeat = 2,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct LayoutArray(NonNull<u64>);

impl IntoIterator for LayoutArray {
    type Item = (Size, Size);
    type IntoIter = LayoutArrayIter;

    fn into_iter(self) -> Self::IntoIter {
        LayoutArrayIter {
            cursor: self.0,
            cmds_rem: 0,
            ranges_rem: 0,
            stride_offset: Size::ZERO,
            repeats: vec![],
        }
    }
}

/// An iterator that "decompresses" a [`LayoutArray`]
/// into `(Size, Size)` pairs.
#[derive(Debug)]
pub struct LayoutArrayIter {
    /// The current word being visited within the array.
    cursor: NonNull<u64>,
    /// The number of commands remaining to be repeated.
    /// If we are not within a repeat, then this is zero.
    cmds_rem: u64,
    /// The number of ranges remaining to be read from
    /// [`LayoutCommand::Ranges`].
    ranges_rem: u64,
    /// The offset of the current element relative to
    /// the start of the current repeat (zero if we are
    /// not repeating). The ranges used to describe an array
    /// are absolute, but only for the first element.
    /// For subsequent elements, we need to add the stride
    /// of the array (the width of a single element) to
    /// get the correct offset.
    stride_offset: Size,
    /// A simulated "stack" of repeat commands. The top of
    /// the stack is the current repeat that we are in.
    repeats: Vec<RepeatFrame>,
}

#[derive(Debug)]
struct RepeatFrame {
    /// The location of the first [`LayoutCommand`] in the series being repeated.
    start: NonNull<u64>,
    /// The byte width of each element of the array.
    stride: Size,
    /// The total number of commands within the series.
    /// We need to store this so that we can reset the number of
    /// commands remaining when we finish an iteration, and start
    /// the next one.
    num_cmds: u64,
    /// The number of iterations remaining.
    rem_iter: u64,
    /// The number of commands remaining to be interpreted
    /// within the previous frame.
    prev_cmds_rem: u64,
    /// The stride offset for the previous repeat.
    prev_stride_offset: Size,
}

impl LayoutArrayIter {
    /// Read the next word from the array.
    unsafe fn advance(&mut self) -> u64 {
        let val = unsafe { self.cursor.read() };
        self.cursor = unsafe { self.cursor.add(1) };
        val
    }

    /// Read the next `N` words from the array.
    unsafe fn advance_n<const N: usize>(&mut self) -> [u64; N] {
        let mut dest = [0; N];
        dest.fill_with(|| unsafe { self.advance() });
        dest
    }

    unsafe fn next_command(&mut self) -> Option<LayoutCommand> {
        let tag = unsafe { self.cursor.read() };
        let tag = unsafe { mem::transmute::<u64, LayoutCommandTag>(tag) };
        match tag {
            LayoutCommandTag::End => None,
            LayoutCommandTag::Ranges => {
                let [_, count] = unsafe { self.advance_n::<2>() };
                Some(LayoutCommand::Ranges { count })
            }
            LayoutCommandTag::Repeat => {
                let [_, stride, count, num_cmds] = unsafe { self.advance_n::<4>() };
                Some(LayoutCommand::Repeat { stride: Size::from_bytes(stride), count, num_cmds })
            }
        }
    }
}

impl Iterator for LayoutArrayIter {
    type Item = (Size, Size);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.ranges_rem > 0 {
                self.ranges_rem -= 1;
                let offsets = unsafe { self.advance_n::<2>() };
                let [base_offset, size] = offsets.map(Size::from_bytes);
                let offset = base_offset + self.stride_offset;
                return Some((offset, size));
            }

            if self.cmds_rem == 0 {
                if let Some(frame) = self.repeats.last_mut() {
                    if frame.rem_iter > 0 {
                        frame.rem_iter -= 1;
                        self.cursor = frame.start;
                        self.cmds_rem = frame.num_cmds;
                        self.stride_offset = self.stride_offset + frame.stride;
                    } else {
                        self.cmds_rem = frame.prev_cmds_rem;
                        self.stride_offset = frame.prev_stride_offset;
                        self.repeats.pop();
                    };
                    continue;
                };
            }

            let in_repeat = !self.repeats.is_empty();
            match unsafe { self.next_command() } {
                // We've reached the end of the layout.
                // There's nothing more to read.
                Some(LayoutCommand::Ranges { count }) => {
                    if in_repeat {
                        self.cmds_rem -= 1;
                    }
                    debug_assert!(count > 0);
                    self.ranges_rem = count;
                }
                Some(LayoutCommand::Repeat { stride, count, num_cmds }) => {
                    let prev_cmds_rem = if in_repeat {
                        self.cmds_rem
                            .checked_sub(1 + num_cmds)
                            .expect("nested Repeat extends past its enclosing Repeat")
                    } else {
                        0
                    };
                    self.cmds_rem = num_cmds;
                    self.repeats.push(RepeatFrame {
                        start: self.cursor,
                        stride,
                        rem_iter: count - 1,
                        num_cmds,
                        prev_cmds_rem,
                        prev_stride_offset: self.stride_offset,
                    });
                }
                None => {
                    return None;
                }
            }
        }
    }
}
