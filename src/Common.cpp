#include <iostream>
using namespace std;

#include "Common.h"

namespace FAES {
  void print_m128i_as_int(__m128i &data) {
    int *ptr = (int*) &data;
  
    for (int i = 0; i < 4; i++) {
      cout << ptr[i] << " ";
    }

    cout << endl;
  }

  void print_m128i_as_byte(__m128i &data) {
    unsigned char *ptr = (unsigned char*) &data;
  
    for (int i = 0; i < 16; i++) {
      cout << ptr[i] << " ";
    }

    cout << endl;  
  }

  void print_m128i_as_byte_int(__m128i &data) {
    unsigned char *ptr = (unsigned char*) &data;
  
    for (int i = 0; i < 16; i++) {
      cout << (int) ptr[i] << " ";
    }

    cout << endl;  
  }

  // Swap the byte-order of a 64-bit number.
  void byteSwap(unsigned long long &data) {
    data = (data >> 56) |
          ((data << 40) & 0x00FF000000000000) |
          ((data << 24) & 0x0000FF0000000000) |
          ((data <<  8) & 0x000000FF00000000) |
          ((data >>  8) & 0x00000000FF000000) |
          ((data >> 24) & 0x0000000000FF0000) |
          ((data >> 40) & 0x000000000000FF00) |
           (data << 56);
  }

  void reverse_m128i(__m128i &data) {
    // Swap hi and low part.
    data = _mm_shuffle_epi32(data, SHUFFLE4_32(2, 3, 0, 1));

    // Byte-swap them individually as 64-bit numbers.
    unsigned long long hi = data[0], low = data[1];
    byteSwap(hi);
    byteSwap(low);

    // Recombine.
    data[0] = hi;
    data[1] = low;
  }

  bool isBigEndian() {
    unsigned int num = 1;
    char *p = (char*) &num;

    if (*(p + sizeof(unsigned int) - 1) == 1) {
      return true;
    }

    return false;
  }
}
