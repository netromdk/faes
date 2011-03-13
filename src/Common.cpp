#include <iostream>
using namespace std;

#include "Common.h"

namespace FAES {
  void print_m128i_as_int(__m128i data) {
    int *ptr = (int*) &data;
  
    for (int i = 0; i < 4; i++) {
      cout << ptr[i] << " ";
    }

    cout << endl;
  }

  void print_m128i_as_byte(__m128i data) {
    unsigned char *ptr = (unsigned char*) &data;
  
    for (int i = 0; i < 16; i++) {
      cout << ptr[i] << " ";
    }

    cout << endl;  
  }

  void print_m128i_as_byte_int(__m128i data) {
    unsigned char *ptr = (unsigned char*) &data;
  
    for (int i = 0; i < 16; i++) {
      cout << (int) ptr[i] << " ";
    }

    cout << endl;  
  }  
}
