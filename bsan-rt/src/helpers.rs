use alloc::alloc::Global;

use hashbrown::{HashMap, HashSet};
use rustc_hash::FxBuildHasher;

#[allow(unused)]
pub type FxHashSet<T, A = Global> = HashSet<T, FxBuildHasher, A>;
pub type FxHashMap<K, V, A = Global> = HashMap<K, V, FxBuildHasher, A>;
