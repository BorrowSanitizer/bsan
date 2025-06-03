#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct DummySpanData(usize);

impl DummySpanData {
    pub fn new() -> DummySpanData {
        DummySpanData(0)
    }
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct DummySpan(usize);

impl DummySpan {
    pub fn new() -> DummySpan {
        DummySpan(0)
    }
    // Returns a DummySpanData with inner zero
    pub fn data(self) -> DummySpan {
        DummySpan::new()
    }
}

impl Into<DummySpan> for DummySpanData {
    fn into(self) -> DummySpan {
        DummySpan(self.0)
    }
}

impl Into<DummySpanData> for DummySpan {
    fn into(self) -> DummySpanData {
        DummySpanData(self.0)
    }
}
