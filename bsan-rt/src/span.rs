use alloc::string::String;
use core::{fmt, ptr};

use crate::sanitizer_common_interface::SanitizerCommon;

unsafe extern "C" {
    // Symbol defined by the linker
    unsafe static __executable_start: [u8; 0];
}

#[derive(Clone, Debug, PartialEq)]
pub enum Symbol {
    Resolved { file: String, line: u32, col: u32 },
    Unknown,
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Symbol::Resolved { file, line, col } => {
                write!(f, "{file}:{line}:{col}")
            }
            Symbol::Unknown => write!(f, "<unknown>:?:?"),
        }
    }
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Span(pub usize);

impl Span {
    pub fn symbolize(self) -> Symbol {
        SanitizerCommon::symbolize(self)
    }
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct FramePtr(pub *const usize);

impl FramePtr {
    pub fn addr(&self) -> usize {
        self.0.addr()
    }

    pub fn caller_span(&self) -> Span {
        Span(unsafe { ptr::read(self.0.add(1)) })
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
}

macro_rules! fp {
    () => {
        FramePtr({
            let fp: usize;

            #[cfg(target_arch = "x86_64")]
            core::arch::asm!("mov {0}, rbp", out(reg) fp);

            #[cfg(target_arch = "aarch64")]
            core::arch::asm!("mov {0}, fp", out(reg) fp);

            fp as *const usize
        })
    };
}

impl Iterator for FramePtr {
    type Item = Span;

    fn next(&mut self) -> Option<Span> {
        let prev = self.prev();
        if *self != prev {
            let ret_addr = self.caller_span();
            *self = prev;
            Some(ret_addr)
        } else {
            None
        }
    }
}
