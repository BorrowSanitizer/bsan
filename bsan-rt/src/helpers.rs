struct FxHashSet<T>(HashSet<T, FxBuildHasher>);

struct FxHashMap<K, V>(HashMap<K, V, FxBuildHasher>);
