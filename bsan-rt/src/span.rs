#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct SpanData(usize);

impl SpanData {
    pub fn new() -> SpanData {
        SpanData(0)
    }
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Span(usize);

impl Span {
    pub fn new() -> Span {
        Span(0)
    }
    // Returns a DummySpanData with inner zero
    pub fn data(self) -> Span {
        Span::new()
    }
}

impl Into<Span> for SpanData {
    fn into(self) -> Span {
        Span(self.0)
    }
}

impl Into<SpanData> for Span {
    fn into(self) -> SpanData {
        SpanData(self.0)
    }
}
