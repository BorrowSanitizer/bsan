#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct DummySpanData(usize);

impl DummySpanData {
    fn new() -> DummySpanData {
        DummySpanData(0)
    }
}

#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct DummySpan(usize);

impl DummySpan {
    fn new() -> DummySpan {
        DummySpan(0)
    }
    // Returns a DummySpanData with inner zero
    fn data() -> DummySpanData {
        DummySpanData::new()
    }
}
