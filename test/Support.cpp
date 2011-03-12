#include <iostream>
using namespace std;

#include "CPU.h"
using namespace FAES::CPU;

int main(int argc, char **argv) {
  if (!cpuidSupported()) {
    cout << "CPUID instruction not supported." << endl;
    return 0;
  }

  cout << "CPUID instruction supported." << endl
       << "SSE supported: " << boolalpha
       << sseSupported() << endl
       << "AES instruction set supported: " << boolalpha
       << aesSupported() << endl;  
  return 0;
}
