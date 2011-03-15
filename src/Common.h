#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <emmintrin.h>

// Shuffle 4 32-bit integers.
#define SHUFFLE4_32(x, y, z, w) (w << 6 | z << 4 | y << 2 | x)

#if !defined (ALIGN16)                            
# if defined (__GNUC__)                           
#  define ALIGN16 __attribute__ ((aligned (16))) 
# else                                            
#  define ALIGN16 __declspec (align (16))       
# endif                                        
#endif

namespace FAES {
  void dumpString(std::string &data);  
  void print_m128i_as_int(__m128i &data);
  void print_m128i_as_byte(__m128i &data);
  void print_m128i_as_byte_int(__m128i &data);
  void byteSwap(unsigned long long &data);
  void reverse_m128i(__m128i &data);
  bool isBigEndian();
}

#endif // COMMON_H
