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
//! 
//! There is one soundness issue with this encoding. A type such as `&mut dyn !Freeze`
//! will be treated as entirely interior mutable. This includes any padding bytes; we do not
//! account for the dynamic alignment of the trait object. This can lead to false negatives. 
//! This limitation could be lifted by adding a vtable entry containing a pointer to the 
//! interior mutability layout.

use alloc::vec::Vec;
use core::mem;
use core::ptr::NonNull;

use crate::helpers::Size;

// Commands to describe individual "segments" of the compressed layout.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum LayoutCommand {
    /// The next segment includes a nonzero `u64` count, followed by
    /// that number of (offset, size) ranges.
    Ranges { count: u64 },
    /// The next segment includes the stride, a nonzero number of
    /// iterations, and a number of commands that should be repeated
    /// for that count.
    Repeat { stride: Size, count: u64, num_cmds: u64 },
    /// Equivalent to a [`LayoutCommand::Repeat`], except instead of
    /// a static count, use the dynamic count of elements provided as
    /// a parameter to the retag intrinsic. This is used to handle a
    /// type where the last or only field is a slice.
    Tail { stride: Size, num_cmds: u64 },
    /// Include every byte from `offset` to the dynamic size of the type
    /// within the layout. This is used to handle dynamic trait objects,
    /// or any other type that is imprecise under the current implementation
    /// of our retag intrinsics.
    Fill { offset: Size },
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
    /// The next bytes are a [`LayoutCommand::Tail`]
    Tail = 3,
    /// The next bytes are a [`LayoutCommand::Fill`]
    Fill = 4,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct LayoutArray(NonNull<u64>);

impl LayoutArray {
    pub fn iter_ranges(&self, size: Size, tail_count: usize) -> LayoutArrayIter {
        LayoutArrayIter {
            cursor: self.0,
            cmds_rem: 0,
            ranges_rem: 0,
            stride_offset: Size::ZERO,
            repeats: vec![],
            size,
            tail_count,
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
    /// The maximum, dynamic size of the type being retagged.
    size: Size,
    /// If the "tail" of this type is a slice, the number of
    /// elements within the slice.
    tail_count: usize,
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

    fn push_repeat(&mut self, rem_iter: u64, stride: Size, num_cmds: u64) {
        let prev_cmds_rem = if !self.repeats.is_empty() {
            self.cmds_rem
                .checked_sub(1 + num_cmds)
                .expect("A repeat's body was longer than its specified length.")
        } else {
            0
        };
        self.cmds_rem = num_cmds;
        self.repeats.push(RepeatFrame {
            start: self.cursor,
            stride,
            rem_iter: rem_iter - 1,
            num_cmds,
            prev_cmds_rem,
            prev_stride_offset: self.stride_offset,
        });
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
            LayoutCommandTag::Tail => {
                let [_, stride, num_cmds] = unsafe { self.advance_n::<3>() };
                Some(LayoutCommand::Tail { stride: Size::from_bytes(stride), num_cmds })
            }
            LayoutCommandTag::Fill => {
                let [_, offset] = unsafe { self.advance_n::<2>() };
                Some(LayoutCommand::Fill { offset: Size::from_bytes(offset) })
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

            if self.cmds_rem == 0
                && let Some(frame) = self.repeats.last_mut()
            {
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

            match unsafe { self.next_command()? } {
                // We've reached the end of the layout.
                // There's nothing more to read.
                LayoutCommand::Ranges { count } => {
                    if !self.repeats.is_empty() {
                        self.cmds_rem -= 1;
                    }
                    debug_assert!(count > 0);
                    self.ranges_rem = count;
                }
                LayoutCommand::Repeat { stride, count, num_cmds } => {
                    self.push_repeat(count, stride, num_cmds);
                }
                LayoutCommand::Tail { stride, num_cmds } => {
                    debug_assert!(
                        self.repeats.is_empty(),
                        "A tail cannot be nested within a repeat!"
                    );
                    if self.tail_count == 0 {
                        // An empty slice.
                        return None;
                    } else {
                        self.push_repeat(self.tail_count as u64, stride, num_cmds);
                    }
                }

                LayoutCommand::Fill { offset } => {
                    debug_assert!(
                        self.repeats.is_empty(),
                        "A fill cannot be nested within a repeat!"
                    );
                    debug_assert!(offset <= self.size);
                    if offset == self.size {
                        return None;
                    }
                    return Some((offset, self.size - offset));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::Size;
    fn ranges(layout: &[u64], size: u64, count: usize) -> Vec<(u64, u64)> {
        let array = LayoutArray(NonNull::from(layout).cast());
        array
            .iter_ranges(Size::from_bytes(size), count)
            .map(|(offset, size)| (offset.bytes(), size.bytes()))
            .collect()
    }

    #[test]
    fn ranges_and_repeat() {
        // [(Cell<u8>, u8); 4]
        let layout = [2, 2, 4, 1, 1, 1, 0, 1, 0];
        assert_eq!(ranges(&layout, 8, 0), [(0, 1), (2, 1), (4, 1), (6, 1)]);
    }

    #[test]
    fn tail() {
        // [(Cell<u8>, u8)]
        let layout = [3, 2, 1, 1, 1, 0, 1, 0];
        assert_eq!(ranges(&layout, 6, 3), [(0, 1), (2, 1), (4, 1)]);
        assert_eq!(ranges(&layout, 0, 0), []);
    }

    #[test]
    fn fill() {
        // dyn Trait
        let layout = [4, 0, 0];
        assert_eq!(ranges(&layout, 24, 0), [(0, 24)]);
        let layout = [1, 1, 0, 1, 4, 8, 0];
        assert_eq!(ranges(&layout, 16, 0), [(0, 1), (8, 8)]);
        assert_eq!(ranges(&layout, 8, 0), [(0, 1)]);
    }
}
