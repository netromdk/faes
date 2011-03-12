#ifndef CPU_H
#define CPU_H

#include <string>

namespace FAES {
  namespace CPU {
    /**
     * CPU Features (from EDX register)
     */
    union CPUFeatures {
      unsigned int raw_data;
      struct {
        /** Floating-point Unit On-Chip */
        unsigned int FPU : 1;

        /** Virtual Mode Extension */
        unsigned int VME : 1;

        /** Debugging Extension */
        unsigned int DE : 1;

        /** Page Size Extension */
        unsigned int PSE : 1;

        /** Time Stamp Counter */
        unsigned int TSC : 1;

        /** Model Specific Registers */
        unsigned int MSR : 1;

        /** Physical Address Extension */
        unsigned int PAE : 1;

        /** Machine-Check Exception */
        unsigned int MCE : 1;

        /** CMPXCHG8 Instruction */
        unsigned int CX8 : 1;

        /** On-chip APIC Hardware */
        unsigned int APIC : 1;
        
        unsigned int RESERVED_1 : 1;

        /** Fast System Call */
        unsigned int SEP : 1;

        /** Memory Type Range Registers */
        unsigned int MTRR : 1;

        /** Page Global Enable */
        unsigned int PGE : 1;

        /** Machine-Check Architechture */
        unsigned int MCA : 1;

        /** Conditional Move Instruction */
        unsigned int CMOV : 1;

        /** Page Attribute Table */
        unsigned int PAT : 1;

        /** Page Size Extension (36 bit) */
        unsigned int PSE36 : 1;

        /** Processor serial number is present and enabled */
        unsigned int PSN : 1;

        /** CLFLUSH Instruction */
        unsigned int CLFSH : 1;
        
        unsigned int RESERVED_2 : 1;

        /** Debug Store */
        unsigned int DS : 1;
        
        /** Thermal Monitor and Software Controlled Clock Facilities */
        unsigned int ACPI : 1;

        /** MMX Technology */
        unsigned int MMX : 1;

        /** FXSAVE and FXSTOR Instructions */
        unsigned int FXSR : 1;

        /** Streaming SIMD Extensions */
        unsigned int SSE : 1;

        /** Streaming SIMD Extensions 2 */
        unsigned int SSE2 : 1;

        /** Self-Snoop */
        unsigned int SS : 1;
        
        /** Hyper-Threading */
        unsigned int HTT : 1;

        /** Thermal Monitor */
        unsigned int TM : 1;
        
        unsigned int RESERVED_3 : 1;

        /** Pending Break Enable */
        unsigned int PBE : 1;
      } features;
    };
    typedef union CPUFeatures CPUFeatures_t;

    /**
     * CPU Features 2 (from ECX register)
     */
    union CPUFeatures2 {
      unsigned int raw_data;
      struct {
        /** Streaming SIMD Extensions 3 */
        unsigned int SSE3 : 1;

        /** PCLMULDQ Instruction */
        unsigned int PCLMULDQ : 1;

        /** 64-bit Debug Store */
        unsigned int DTES64 : 1;

        /** MONITOR/MWAIT */
        unsigned int MONITOR : 1;

        /** CPL Qualified Debug Store */
        unsigned int DS_CPL : 1;

        /** Virtual Machine Extensions */
        unsigned int VMX : 1;

        /** Safer Mode Extensions */
        unsigned int SMX : 1;

        /** Enhanced Intel SpeedStep Technology */
        unsigned int EIST : 1;

        /** Thermal Monitor 2 */
        unsigned int TM2 : 1;

        /** Supplemental Streaming SIMD Extensions 3 */
        unsigned int SSSE3 : 1;

        /** L1 Context ID */
        unsigned int CNXT_ID : 1;
        
        unsigned int RESERVED_1 : 1;

        /** Fused Multiply Add */
        unsigned int FMA : 1;

        /** CMPXCHG16B */
        unsigned int CX16 : 1;

        /** xTPR Update Control */
        unsigned int xTPR : 1;

        /** Perfmon and Debug Capability */
        unsigned int PDCM : 1;

        unsigned int RESERVED_2 : 1;
        
        /** Process Context Identifiers */
        unsigned int PCID : 1;

        /** Direct Cache Access */
        unsigned int DCA : 1;

        /** Streaming SIMD Extensions 4.1 */
        unsigned int SSE4_1 : 1;

        /** Streaming SIMD Extensions 4.2 */
        unsigned int SSE4_2 : 1;        

        /** Extended xAPIC Support */
        unsigned int x2APIC : 1;
        
        /** MOVBE Instruction */
        unsigned int MOVBE : 1;
        
        /** POPCNT Instruction */
        unsigned int POPCNT : 1;

        /** Time Stamp Counter Deadline */
        unsigned int TSC_DEADLINE : 1;

        /** AES Instruction Extensions */
        unsigned int AES : 1;

        /** XSAVE/XSTOR States */
        unsigned int XSAVE : 1;

        /** OS-Enabled Extended State Management */
        unsigned int OSXSAVE : 1;

        /** Advanced Vector Extensions */
        unsigned int AVX : 1;
        
        unsigned int RESERVED_3 : 1;
        unsigned int RESERVED_4 : 1; 
      } features;
    };
    typedef union CPUFeatures2 CPUFeatures2_t;    

    /**
     * Extended CPU features.
     */
    union CPUEFeatures {
      unsigned int raw_data;
      struct {
        unsigned int RESERVED_1 : 11;

        /** Supports the SYSCALL and SYSRET instructions. */
        unsigned int SYSCALL : 1;
        
        unsigned int RESERVED_2 : 8;

        /** Execution Disable Bit (when PAE enabled). */
        unsigned int XDBit : 1;
        
        unsigned int RESERVED_3 : 8;

        /** Intel 64 Instruction Set Architecture. */
        unsigned int I64 : 1;
        
        unsigned int RESERVED_4 : 2;
      } features;
    };
    typedef union CPUEFeatures CPUEFeatures_t;

    /**
     * Extended CPU features 2.
     */
    union CPUEFeatures2 {
      unsigned int raw_data;
      struct {
        /**
         * LAHF and SAHF instructions available when IA-32e mode is
         * enabled and the processor is operating in the 64-bit
         * sub-mode.
         */
        unsigned int LAHF : 1;
        
        unsigned int RESERVED_1 : 31;
      } features;
    };
    typedef union CPUEFeatures2 CPUEFeatures2_t;

    /**
     * Detects whether the cpuid instruction is supported.
     */
    bool cpuidSupported();

    /**
     * Invokes the cpuid instruction with the given opcode and returns
     * the result of EAX, EBX, ECX and EDX in the array.
     */
    void cpuid(unsigned int opcode, unsigned int result[4]);

    /**
     * Determines whether SSE is supported.
     */
    bool sseSupported();    

    /**
     * Determines whether the AES instruction set is supported.
     */
    bool aesSupported();
  }
}

#endif // CPU_H
