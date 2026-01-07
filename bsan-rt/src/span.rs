use core::ptr;

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
    pub fn new() -> Span {
        Span(0)
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
pub struct FramePointer(pub *const usize);

impl FramePointer {
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
        #[cfg(feature = "pic")]
        {
            let ip = unsafe { ptr::read(self.0.add(1)) };
            let base = unsafe { __executable_start.as_ptr() as usize };
            Span(ip - base)
        }

        #[cfg(not(feature = "pic"))]
        {
            Span(unsafe { ptr::read(self.0.add(1)) })
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
        FramePointer({
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
