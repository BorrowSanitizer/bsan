#include <utility>

extern "C" void swap_aliased(int *a, int *b) { std::swap(*a, *b); }
