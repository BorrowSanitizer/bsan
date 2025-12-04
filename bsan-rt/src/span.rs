use core::arch::asm;
use core::ptr;

use cfg_if::cfg_if;

use crate::SpanData;

unsafe extern "C" {
    // Symbol defined by the linker
    unsafe static __executable_start: [u8; 0];
}

#[derive(Copy, Clone, Debug)]
pub struct Span(SpanData);

impl Span {
    pub fn new(span_data: SpanData) -> Span {
        Span(span_data)
    }
    pub fn span_data(self) -> SpanData {
        self.0
    }
    pub fn addr(self) -> usize {
        self.0.ip()
    }
    pub fn print_stack_trace(&self) {
        self.0.print_stack_trace();
    }
}

/*

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

     */
