#ifndef COMMON_H
#define COMMON_H

#include <emmintrin.h>

// Shuffle 4 32-bit integers.
#define SHUFFLE4_32(x, y, z, w) (w << 6 | z << 4 | y << 2 | x)

namespace FAES {
  void print_m128i_as_int(__m128i data);
  void print_m128i_as_byte(__m128i data);
}

#endif // COMMON_H
