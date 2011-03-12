#include "CPU.h"
using namespace FAES;

bool CPU::cpuidSupported() {
  // This method uses the ID flag in bit 21 of the EFLAGS register. If
  // software can change the value of this flag, the CPUID instruction
  // is executable.
  unsigned int res;
  __asm__("mov %%ecx, %%eax;"
          "xor $200000, %%eax;"
          "xor %%ecx, %%eax;"
          "je no;"
          "mov $1, %%eax;"
          "jmp end;"
          "no: mov $0, %%eax;"
          "end:;"
          : "=a" (res)
          :
          : "cc"); 
  
  return res > 0;
}

void CPU::cpuid(unsigned int opcode, unsigned int result[4]) {
  if(!cpuidSupported()) return;

  // PIC compliant version
  __asm__("cpuid;"
          "movl %%ebx, %1;" 
          : "=a" (result[0]), // EAX register -> result[0]
            "=r" (result[1]), // EBX register -> result[1]
            "=c" (result[2]), // ECX register -> result[2]
            "=d" (result[3])  // EDX register -> result[3]
          : "0" (opcode)
          : "cc");
}

bool CPU::aesSupported() {
  CPUFeatures2_t features;
  unsigned int res[4];
  cpuid(1, res);
  features.raw_data = res[3];
  return features.features.AES == 1;
}
