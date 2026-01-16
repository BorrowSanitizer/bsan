use alloc::string::String;
use core::fmt::{self, Debug, Display};
use core::ptr;

unsafe extern "C" {
    // Symbol defined by the linker
    unsafe static __executable_start: [u8; 0];
}

#[derive(Clone, Debug, PartialEq)]
pub struct SrcLoc {
    pub file: String,
    pub line: u32,
    pub col: u32,
}

impl fmt::Display for SrcLoc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: line {}, column {}", self.file, self.line, self.col)
    }
}

#[derive(Copy, Clone, PartialEq)]
pub struct Span {
    fp: FramePointer,
    /// The adjusted PC address as retrieved from sanitizer_common's stack depot.
    /// This points to the call instruction rather than the return address.
    ip: usize,
}

impl Span {
    pub fn new(fp: usize, ip: usize) -> Self {
        Self { fp: FramePointer(fp as *const usize), ip }
    }

    pub fn ip(&self) -> usize {
        self.ip
    }

    pub fn fp(&self) -> FramePointer {
        self.fp
    }

    /// Try to obtain a `SrcLoc` for this span's ip.
    pub fn source_location(&self) -> Option<SrcLoc> {
        #[cfg(not(test))]
        {
            crate::sanitizer_common_interface::symbolize_pc_into(self.ip)
        }
        #[cfg(test)]
        {
            None
        }
    }
}

impl Debug for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Span {{ ip: 0x{:x}, fp: 0x{:x} }}", self.ip, self.fp.addr())
    }
}

impl Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.source_location() {
            Some(loc) => write!(f, "{}", loc),
            None => write!(f, "ip 0x{:x}", self.ip),
        }
    }
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct FramePointer(pub *const usize);

impl FramePointer {
    pub fn addr(&self) -> usize {
        self.0.addr()
    }

    pub fn ip(&self) -> usize {
        unsafe { ptr::read(self.0.add(1)) }
    }

    pub fn unwind(mut self, num: usize) -> Self {
        for _ in 0..num {
            self = self.prev();
        }
        self
    }

    pub fn prev(self) -> Self {
        if self.0.is_null() {
            self
        } else {
            let fp = self.0.cast::<*mut usize>();
            let prev_fp = unsafe { ptr::read(fp) };
            Self(prev_fp)
        }
    }

    pub const fn null() -> Self {
        Self(ptr::null())
    }
}

// impl Iterator for FramePointer {
//     type Item = Span; // return address

//     fn next(&mut self) -> Option<Span> {
//         let prev = self.prev();
//         if *self != prev {
//             let ret_addr = self.ip();
//             *self = prev;
//             Some(ret_addr)
//         } else {
//             None
//         }
//     }
// }
