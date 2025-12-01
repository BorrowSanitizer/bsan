use core::arch::asm;
use core::ptr;

use cfg_if::cfg_if;

#[cfg(not(test))]
use crate::sanitizer_common_interface::capture_current_stack_trace;

unsafe extern "C" {
    // Symbol defined by the linker
    unsafe static __executable_start: [u8; 0];
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct SpanData(usize);

impl SpanData {
    pub fn new() -> SpanData {
        SpanData(0)
    }

    pub fn resolve_from(_span: Span) -> Self {
        todo!()
    }
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Span(pub usize);

impl Span {
    /// Always inlined to not add an extra frame for this function to the stack.
    /// This function should therefore only be called from the __bsan_write/read/retag functions.
    /// TODO: maybe move the implementation into SpanData(?) and move this into lib.rs.
    #[inline(always)]
    pub fn new() -> Span {
        #[cfg(not(test))]
        {
            let depth = 2; // only capture the caller frame (2 necessary for addititional call to LLVM wrapper)
            let stack_id = capture_current_stack_trace(Some(depth));
            return Span(stack_id.0 as usize);
        }
        Span(0)
    }
    // Returns a DummySpanData with inner zero
    pub fn data(self) -> Span {
        Span::new()
    }
    // Finds a frame pointer from the current call stack walking backwards
    pub fn find_fp(&self) -> Option<FramePointer> {
        let mut fp = FramePointer::current();
        loop {
            let prev = fp.prev();
            if fp == prev {
                break;
            }
            let ip = fp.ip();
            if ip == *self {
                return Some(fp);
            }
            fp = prev;
        }
        None
    }
}

impl From<SpanData> for Span {
    fn from(val: SpanData) -> Self {
        Span(val.0)
    }
}

impl From<Span> for SpanData {
    fn from(val: Span) -> Self {
        SpanData(val.0)
    }
}
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct FramePointer(*const usize);

impl FramePointer {
    pub fn addr(&self) -> usize {
        self.0.addr()
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub fn current() -> Self {
        let fp: usize;
        #[cfg(target_arch = "x86_64")]
        unsafe {
            asm!("mov {0}, rbp", out(reg) fp, options(nomem, nostack, preserves_flags));
        }
        #[cfg(target_arch = "aarch64")]
        unsafe {
            asm!("mov {0}, fp", out(reg) fp, options(nomem, nostack, preserves_flags));
        }
        Self(fp as *const usize)
    }

    pub fn ip(&self) -> Span {
        cfg_if! {
            if #[cfg(feature = "pic")] {
                let ip = unsafe { ptr::read(self.0.add(1)) };
                let base = unsafe { __executable_start.as_ptr() as usize };
                Span(ip - base)
            }else{
                Span(unsafe { ptr::read(self.0.add(1)) })
            }
        }
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

impl Iterator for FramePointer {
    type Item = Span; // return address

    fn next(&mut self) -> Option<Span> {
        let prev = self.prev();
        if *self != prev {
            let ret_addr = self.ip();
            *self = prev;
            Some(ret_addr)
        } else {
            None
        }
    }
}
