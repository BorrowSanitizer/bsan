use core::ptr;
use core::ptr::NonNull;

use cfg_if::cfg_if;

unsafe extern "C" {
    // Symbol defined by the linker
    unsafe static __executable_start: [u8; 0];
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Span(Option<NonNull<usize>>);

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct FramePtr(pub *const usize);

impl FramePtr {
    pub fn addr(&self) -> usize {
        self.0.addr()
    }

    pub fn unwind(mut self, num: usize) -> Self {
        for _ in 0..num {
            self = self.prev();
        }
        self
    }

    pub fn ip(&self) -> Span {
        if self.0.is_null() {
            Span(None)
        } else {
            let ip = unsafe { ptr::read(self.0.add(1)) };
            cfg_if! {
                if #[cfg(feature = "pic")] {
                    let base = unsafe { __executable_start.as_ptr() as usize };
                    Span(Some(unsafe { NonNull::new_unchecked((ip - base) as *mut usize) }))
                }else{
                    Span(Some(unsafe { NonNull::new_unchecked(ip as *mut usize) }))
                }
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
