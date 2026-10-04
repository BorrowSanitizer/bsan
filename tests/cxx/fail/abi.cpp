struct Pair {
  int *first;
  int *second;
};

extern "C" Pair swap_pair(Pair pair) { return {pair.second, pair.first}; }
