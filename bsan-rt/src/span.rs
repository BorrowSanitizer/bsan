use alloc::string::String;
use core::fmt::{self, Debug, Display};
use core::ptr;

#[cfg(not(test))]
use crate::sanitizer_common_interface;

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
        write!(f, "{}:{}:{}", self.file, self.line, self.col)
    }
}

#[derive(Copy, Clone, PartialEq)]
pub struct Span {
    fp: FramePointer,
    /// The adjusted PC address as retrieved from sanitizer_common's stack depot.
    /// This points to the call instruction rather than the return address.
    ip: usize,
    #[cfg(not(test))]
    stack_trace_id: crate::sanitizer_common_interface::StackTraceId,
}

impl Span {
    pub fn new(fp: usize, ip: usize) -> Self {
        #[cfg(not(test))]
        {
            let stack_trace_id =
                sanitizer_common_interface::capture_current_stack_trace(ip, fp, Some(3)); // TODO make max depth user-configurable
            Self { fp: FramePointer(fp as *const usize), ip, stack_trace_id }
        }
        #[cfg(test)]
        {
            Self { fp: FramePointer(fp as *const usize), ip }
        }
    }

    pub fn ip(&self) -> usize {
        self.ip
    }

    pub fn fp(&self) -> FramePointer {
        self.fp
    }

    pub fn print_stack_trace(&self) {
        #[cfg(not(test))]
        crate::sanitizer_common_interface::print_stack_trace(Some(self.stack_trace_id));
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
            _ => write!(f, "ip 0x{:x}", self.ip),
        }
    }
}

#[macro_export]
macro_rules! span {
    () => {{
        let fp = fp!();
        Span::new(fp.addr(), fp.ip())
    }};
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

#[macro_export]
macro_rules! fp {
    () => {
            FramePointer({
                let fp: usize;
                #[cfg(target_arch = "x86_64")]
                core::arch::asm!("mov {0}, rbp", out(reg) fp, options(nomem, nostack, preserves_flags));
                #[cfg(target_arch = "aarch64")]
                core::arch::asm!("mov {0}, fp", out(reg) fp, options(nomem, nostack, preserves_flags));
                fp as *const usize
            })
    };
}
