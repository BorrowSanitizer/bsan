// Taken from https://github.com/rust-lang/hashbrown

#[cfg(test)]
mod tests {
    use hashbrown::HashMap;

    const N: u32 = 3;
    #[test]
    fn test_lots_of_insertions() {
        let mut m = HashMap::new();

        // Try this a few times to make sure we never screw up the hashmap's
        // internal state.
        for _ in 0..N {
            assert!(m.is_empty());

            for i in 1..(N + 1) {
                assert!(m.insert(i, i).is_none());

                for j in 1..=i {
                    let r = m.get(&j);
                    assert_eq!(r, Some(&j));
                }

                for j in i + 1..(N + 1) {
                    let r = m.get(&j);
                    assert_eq!(r, None);
                }
            }

            for i in (N + 1)..(2 * N + 1) {
                assert!(!m.contains_key(&i));
            }

            // remove forwards
            for i in 1..(N + 1) {
                assert!(m.remove(&i).is_some());

                for j in 1..=i {
                    assert!(!m.contains_key(&j));
                }

                for j in i + 1..(N + 1) {
                    assert!(m.contains_key(&j));
                }
            }

            for i in 1..(N + 1) {
                assert!(!m.contains_key(&i));
            }

            for i in 1..(N + 1) {
                assert!(m.insert(i, i).is_none());
            }

            // remove backwards
            for i in (1..(N + 1)).rev() {
                assert!(m.remove(&i).is_some());

                for j in i..(N + 1) {
                    assert!(!m.contains_key(&j));
                }

                for j in 1..i {
                    assert!(m.contains_key(&j));
                }
            }
        }
    }
}
