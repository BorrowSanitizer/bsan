//@run:1
//This is a direct copy of the test `mlu::mlu` from `lcms2` at 6.0.0.

use lcms2::{Locale, MLU};

fn main() {
    let _ = MLU::new(0);
    let mut m = MLU::new(1);
    assert!(m.set_text("Hello 世界！", Locale::none()));
    assert_eq!(Ok("Hello 世界！".to_owned()), m.text(Locale::none()));
    assert!(!m.set_text_ascii("エッロル", Locale::none()));

    assert!(m.set_text("a", Locale::new("en_US")));
    assert_eq!("a", m.text_ascii(Locale::new("en_US")).unwrap());

    let mut m = MLU::new(1);
    assert!(m.set_text_ascii("OK", Locale::none()));
    assert_eq!("OK", m.text_ascii(Locale::none()).unwrap());
}