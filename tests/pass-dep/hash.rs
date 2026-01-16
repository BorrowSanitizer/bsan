//@run:0
use hashbrown::HashMap;

fn main() {
    let mut map = HashMap::<(), ()>::default();
    map.insert((), ());
}
