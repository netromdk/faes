#include <iostream>
using namespace std;

#include "CPU.h"
using namespace FAES;

int main(int argc, char **argv) {
  if (!CPU::cpuidSupported()) {
    cout << "CPUID instruction not supported." << endl;
    return 0;
  }

  cout << "CPUID instruction supported." << endl
       << "AES instruction set supported: " << boolalpha
       << CPU::aesSupported() << endl;  
  return 0;
}
