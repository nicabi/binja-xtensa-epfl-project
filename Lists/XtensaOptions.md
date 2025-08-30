This is a list of all possible options available in Xtensa. 
It can help to get an overview of what needs to be implemented for the decompiler

# "Options for Additional Instructions" on page 53
Code Density Option                       - adds 16-bit encodings of the most frequently used 24-bit instructions for higher code density.
Loop Option                               - adds a zero overhead loop mechanism that eliminates branch instructions at loop ends.
Extended L32R Option                      - extends the addressing mode capabilities of the L32R instruction.
16-bit Integer Multiply Option            - adds 16x16 multiplication instructions with 32-bit results.
32-bit Integer Multiply Option            - adds 32x32 multiplication instructions producing 64-bit results.
32-bit Integer Divide Option              - implements 32-bit division and remainder instructions.
MAC16 Option                              - adds multiply-accumulate functions for DSP applications.
Miscellaneous Operations Option           - provides various application-specific instructions.
Coprocessor Option                        - enables coprocessor state grouping with lazy context switching.
Boolean Option                            - adds Boolean registers usable as branch conditions.
Floating-Point Coprocessor Option         - adds single-precision floating-point unit.
Multiprocessor Synchronization Option     - adds memory ordering instructions for multiprocessing.
Conditional Store Option                  - adds compare-and-swap atomic operations.

# "Options for Interrupts and Exceptions" on page 82
Exception Option                          - provides basic exception handling capabilities.
Relocatable Vector Option                 - enables runtime relocation of exception vectors.
Unaligned Exception Option                - generates exceptions for unaligned memory accesses.
Interrupt Option                          - implements software-prioritized interrupt system.
High-Priority Interrupt Option            - adds hardware-prioritized interrupts.
Timer Interrupt Option                    - provides timer-based interrupts.

# "Options for Local Memory" on page 111
Instruction Cache Option                  - adds configurable instruction cache interface.
Instruction Cache Test Option             - enables cache tag/data access instructions.
Instruction Cache Index Lock Option       - adds per-index cache locking.
Data Cache Option                         - adds configurable data cache interface.
Data Cache Test Option                    - enables data cache tag access instructions.
Data Cache Index Lock Option              - adds per-index data cache locking.
Instruction RAM Option                    - adds local instruction memory interface.
Instruction ROM Option                    - adds local instruction ROM interface.
Data RAM Option                           - adds local data memory interface.
Data ROM Option                           - adds local data ROM interface.
XLMI Option                               - provides extended local memory interface for non-memory devices.
Hardware Alignment Option                 - enables hardware handling of unaligned accesses.
Memory ECC/Parity Option                  - supports ECC/parity for caches and local memories.

# "Options for Memory Protection and Translation" on page 138
Region Protection Option                  - provides memory protection in eight segments.
Region Translation Option                 - adds segment-based memory translation.
MMU Option                                - implements full paging virtual memory management.

# "Options for Other Purposes" on page 179
Windowed Register Option                  - adds register windowing for performance and code density.
Processor Interface Option                - provides external memory bus interface.
Miscellaneous Special Registers Option    - adds application-specific scratch registers.
Thread Pointer Option                     - provides thread-specific pointer register.
Processor ID Option                       - adds processor identification register.
Debug Option                              - implements debugging features like breakpoints.
Trace Port Option                         - adds hardware tracing support.
