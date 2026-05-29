//@run:1
// This is adapted from `cannot_open_with_different_compression` from lsmlite-rs at version 0.1.0

use lsmlite_rs::*;

fn main() {
    let db_path = "/tmp".to_string();
    let db_base_name = format!("test");

    let db_conf = DbConf::new_with_parameters(
        db_path,
        db_base_name,
        LsmMode::LsmBackgroundMerger,
        LsmHandleMode::ReadWrite,
        None,
        LsmCompressionLib::ZStd,
    );

    let mut db: LsmDb = Default::default();

    let rc = db.initialize(db_conf.clone());
    assert_eq!(rc, Ok(()));

    db.connect().unwrap();
}
